require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { GoogleGenAI } = require('@google/genai');
const nodemailer = require('nodemailer');
const multer = require('multer');

// Multer 설정 (메모리 저장)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'yaktong-secret-key-2024';

// Email Transporter Setup (Gmail SMTP)
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS  // Gmail 앱 비밀번호
  }
});

// 인증코드 생성 (6자리 숫자)
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// 인증 이메일 발송
async function sendVerificationEmail(email, code) {
  const mailOptions = {
    from: `"약통" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: '[약통] 이메일 인증 코드',
    html: `
      <div style="font-family: 'Apple SD Gothic Neo', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #5FC3B0;">약통 이메일 인증</h2>
        <p>안녕하세요, 약통 회원가입을 위한 인증 코드입니다.</p>
        <div style="background-color: #f5f5f5; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
          <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #333;">${code}</span>
        </div>
        <p style="color: #666;">이 코드는 10분간 유효합니다.</p>
        <p style="color: #999; font-size: 12px;">본인이 요청하지 않았다면 이 이메일을 무시하세요.</p>
      </div>
    `
  };

  await emailTransporter.sendMail(mailOptions);
}

// PostgreSQL Setup
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Gemini AI Setup
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
const ABS_STORE = 'fileSearchStores/mfdsdrugstore1765819248-f2vhzseniw9t';
const REL_STORE = 'fileSearchStores/ymydstore1765817115-9jn4gkjo6hbb';
const AI_SYSTEM_PROMPT = `당신은 '약통'의 AI 어시스턴트입니다. 사용자는 현직 약사이며, 동료 약사에게 자문을 구하듯 대화합니다.

## 지식 소스
1. **ABS_STORE**: 식약처 허가사항, 성분정보, 용법용량, 금기, 상호작용 등 공식 데이터
2. **REL_STORE**: 약문약답 임상 사례, 복약지도 노하우, 현장 경험 공유

## 정보 소스 우선순위
1순위: ABS_STORE - 허가사항/공식 기준
2순위: REL_STORE - 임상 사례/현장 노하우
3순위: 일반 약학 지식 - 스토어에 없을 때만

## 응답 원칙

### 1. 전문가 눈높이
- 성분명(일반명) 중심으로 답변
- 약리기전, DDI, PK/PD 등 전문 용어 그대로 사용
- 불필요한 기초 설명 생략

### 2. 정보 검색
- 모든 질문에 두 스토어 우선 검색
- 허가사항/금기/용량 → ABS_STORE 우선
- 실제 투약 경험/대체약 추천 → REL_STORE 참고
- 상충 시 ABS_STORE 우선, 단 REL_STORE의 임상 관점도 병기

### 3. 응답 형식
[답변]
(간결하고 핵심 중심)

[근거]
- 공식: {파일명}
- 임상: {파일명}
- 또는 [일반 약학 지식]

### 4. 정보 부재 시
- "해당 내용은 DB에서 확인되지 않습니다"
- 추측 금지, 있는 정보만 제공

### 5. 톤
- 동료 약사 간 대화처럼 간결하고 실무적
- 반말/존댓말 사용자 스타일에 맞춤
- 핵심만 빠르게 전달`;

// 세션별 대화 히스토리 저장 (TTL + 최대 턴 제한)
const aiSessions = new Map(); // sessionId -> { history: Content[], updatedAt: number }
const MAX_TURNS = 30;
const TTL_MS = 30 * 60 * 1000; // 30분

function getSession(sessionId) {
  const now = Date.now();
  const s = aiSessions.get(sessionId);
  if (s && (now - s.updatedAt) < TTL_MS) {
    s.updatedAt = now;
    return s;
  }
  const fresh = { history: [], updatedAt: now };
  aiSessions.set(sessionId, fresh);
  return fresh;
}

function pushTurn(session, content) {
  session.history.push(content);
  if (session.history.length > MAX_TURNS) {
    session.history.splice(0, session.history.length - MAX_TURNS);
  }
}

// 타임아웃 + 재시도 헬퍼
async function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("AI_TIMEOUT")), ms)),
  ]);
}

async function generateWithRetry(payload, retries = 2) {
  let lastErr;
  for (let i = 0; i <= retries; i++) {
    try {
      return await withTimeout(ai.models.generateContent(payload), 35000);
    } catch (e) {
      lastErr = e;
      const msg = String(e?.message ?? e);
      const retryable = msg.includes("429") || msg.includes("503") || msg.includes("504") || msg.includes("RESOURCE_EXHAUSTED");
      if (!retryable || i === retries) break;
      await new Promise(r => setTimeout(r, 500 * (2 ** i)));
    }
  }
  throw lastErr;
}

// 응답 텍스트 추출 (parts 전체 결합)
function extractText(result) {
  if (typeof result?.text === "string" && result.text.trim()) return result.text.trim();
  const parts = result?.candidates?.[0]?.content?.parts ?? [];
  const joined = parts.map(p => p?.text).filter(Boolean).join("").trim();
  return joined;
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Initialize database tables
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(100) NOT NULL,
        phone VARCHAR(20),
        profile_image TEXT,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add profile_image column if not exists (for existing DB)
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_image TEXT
    `);

    // Add email verification columns
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE
    `);
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_code VARCHAR(6)
    `);
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_expires TIMESTAMP
    `);

    // Add is_blocked column if not exists (for existing DB)
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT FALSE
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        category VARCHAR(50) DEFAULT 'daily',
        is_anonymous BOOLEAN DEFAULT FALSE,
        author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        author_name VARCHAR(100),
        images TEXT,
        like_count INTEGER DEFAULT 0,
        dislike_count INTEGER DEFAULT 0,
        comment_count INTEGER DEFAULT 0,
        view_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add images column if not exists (for existing databases)
    await pool.query(`
      ALTER TABLE posts ADD COLUMN IF NOT EXISTS images TEXT
    `).catch(() => {});

    await pool.query(`
      ALTER TABLE posts ADD COLUMN IF NOT EXISTS dislike_count INTEGER DEFAULT 0
    `).catch(() => {});

    await pool.query(`
      CREATE TABLE IF NOT EXISTS post_likes (
        id SERIAL PRIMARY KEY,
        post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(post_id, user_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
        parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        author_name VARCHAR(100),
        like_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add parent_id column if not exists (for existing DB)
    await pool.query(`
      ALTER TABLE comments ADD COLUMN IF NOT EXISTS parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS comment_likes (
        id SERIAL PRIMARY KEY,
        comment_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(comment_id, user_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS notices (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add author_id and is_pinned columns if not exists
    await pool.query(`
      ALTER TABLE notices ADD COLUMN IF NOT EXISTS author_id INTEGER REFERENCES users(id) ON DELETE SET NULL
    `);
    await pool.query(`
      ALTER TABLE notices ADD COLUMN IF NOT EXISTS author_name VARCHAR(100) DEFAULT '관리자'
    `);
    await pool.query(`
      ALTER TABLE notices ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN DEFAULT FALSE
    `);

    // Notifications table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        message TEXT,
        post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
        comment_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
        from_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        from_user_name VARCHAR(100),
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add dislike_count to posts and comments
    await pool.query(`
      ALTER TABLE posts ADD COLUMN IF NOT EXISTS dislike_count INTEGER DEFAULT 0
    `);
    await pool.query(`
      ALTER TABLE comments ADD COLUMN IF NOT EXISTS dislike_count INTEGER DEFAULT 0
    `);

    // Post dislikes table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS post_dislikes (
        id SERIAL PRIMARY KEY,
        post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(post_id, user_id)
      )
    `);

    // Comment dislikes table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS comment_dislikes (
        id SERIAL PRIMARY KEY,
        comment_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(comment_id, user_id)
      )
    `);

    // Jobs table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS jobs (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        type VARCHAR(20) DEFAULT 'hiring',
        work_type VARCHAR(50) DEFAULT '풀타임',
        category VARCHAR(50) DEFAULT '약국',
        location VARCHAR(100),
        address TEXT,
        latitude DECIMAL(10, 8),
        longitude DECIMAL(11, 8),
        work_days VARCHAR(100),
        work_hours VARCHAR(100),
        salary_min INTEGER,
        salary_max INTEGER,
        salary_negotiable BOOLEAN DEFAULT FALSE,
        salary_type VARCHAR(20) DEFAULT '월급',
        is_after_tax BOOLEAN DEFAULT FALSE,
        software VARCHAR(100),
        dispenser VARCHAR(100),
        automation TEXT,
        pharmacist_count INTEGER,
        staff_count INTEGER,
        benefits TEXT,
        description TEXT,
        contact_phone VARCHAR(50),
        author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        author_name VARCHAR(100),
        view_count INTEGER DEFAULT 0,
        apply_count INTEGER DEFAULT 0,
        is_premium BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        bumped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add salary_type column if not exists (for existing DB)
    await pool.query(`
      ALTER TABLE jobs ADD COLUMN IF NOT EXISTS salary_type VARCHAR(20) DEFAULT '월급'
    `);

    // Add is_completed column if not exists
    await pool.query(`
      ALTER TABLE jobs ADD COLUMN IF NOT EXISTS is_completed BOOLEAN DEFAULT FALSE
    `);

    // Job likes table (관심공고용)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS job_likes (
        id SERIAL PRIMARY KEY,
        job_id INTEGER REFERENCES jobs(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(job_id, user_id)
      )
    `);

    // Migrate data from job_bookmarks to job_likes if exists
    await pool.query(`
      INSERT INTO job_likes (job_id, user_id, created_at)
      SELECT job_id, user_id, created_at FROM job_bookmarks
      ON CONFLICT (job_id, user_id) DO NOTHING
    `).catch(() => {});

    // Pharmacies (약국 매물) table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS pharmacies (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        transaction_type VARCHAR(20) DEFAULT 'rent',
        region VARCHAR(100),
        address TEXT,
        latitude DECIMAL(10, 8),
        longitude DECIMAL(11, 8),
        commercial_area VARCHAR(50),
        area DECIMAL(10, 2),
        supply_area DECIMAL(10, 2),
        management_cost INTEGER,
        pharmacy_type VARCHAR(50),
        monthly_prescription_min INTEGER,
        monthly_prescription_max INTEGER,
        daily_sales INTEGER,
        deposit INTEGER,
        monthly_rent INTEGER,
        premium INTEGER,
        description TEXT,
        contact_phone VARCHAR(50),
        author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        author_name VARCHAR(100),
        view_count INTEGER DEFAULT 0,
        is_premium BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        bumped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Pharmacy likes table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS pharmacy_likes (
        id SERIAL PRIMARY KEY,
        pharmacy_id INTEGER REFERENCES pharmacies(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(pharmacy_id, user_id)
      )
    `);

    // Add is_completed column to pharmacies if not exists
    await pool.query(`
      ALTER TABLE pharmacies ADD COLUMN IF NOT EXISTS is_completed BOOLEAN DEFAULT FALSE
    `);

    // Add consulting_fee column to pharmacies if not exists
    await pool.query(`
      ALTER TABLE pharmacies ADD COLUMN IF NOT EXISTS consulting_fee INTEGER
    `);

    // ==================== Reputation System Tables ====================

    // Add user_type column to users (general, pharmacist, pharmacy_owner)
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS user_type VARCHAR(20) DEFAULT 'general'
    `);

    // Add reputation_score column to users
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS reputation_score INTEGER DEFAULT 0
    `);

    // Add license_status column to users (none, pending, approved, rejected)
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS license_status VARCHAR(20) DEFAULT 'none'
    `);

    // License verifications table (약사면허증/약국개설등록증 인증 요청)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS license_verifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        request_type VARCHAR(20) NOT NULL,
        license_image TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        rejection_reason TEXT,
        reviewer_id INTEGER REFERENCES users(id),
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TIMESTAMP
      )
    `);

    // Reputation votes table (인기도 투표)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reputation_votes (
        id SERIAL PRIMARY KEY,
        voter_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        target_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        vote_type INTEGER NOT NULL CHECK (vote_type IN (1, -1)),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Blocked users table (사용자 차단)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS blocked_users (
        id SERIAL PRIMARY KEY,
        blocker_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        blocked_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(blocker_id, blocked_id)
      )
    `);

    // Meetings table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS meetings (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        image_base64 TEXT,
        category VARCHAR(50) NOT NULL,
        status VARCHAR(20) DEFAULT 'recruiting',
        location VARCHAR(255) NOT NULL,
        member_count INTEGER DEFAULT 1,
        max_members INTEGER DEFAULT 100,
        author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Meeting members table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS meeting_members (
        id SERIAL PRIMARY KEY,
        meeting_id INTEGER REFERENCES meetings(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        is_host BOOLEAN DEFAULT FALSE,
        status VARCHAR(20) DEFAULT 'approved',
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(meeting_id, user_id)
      )
    `);

    // Add status column if not exists (migration)
    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='meeting_members' AND column_name='status') THEN
          ALTER TABLE meeting_members ADD COLUMN status VARCHAR(20) DEFAULT 'approved';
        END IF;
      END $$;
    `);

    // Add last_read_at column if not exists (for unread message count)
    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='meeting_members' AND column_name='last_read_at') THEN
          ALTER TABLE meeting_members ADD COLUMN last_read_at TIMESTAMP;
        END IF;
      END $$;
    `);

    // Meeting likes table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS meeting_likes (
        id SERIAL PRIMARY KEY,
        meeting_id INTEGER REFERENCES meetings(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(meeting_id, user_id)
      )
    `);

    // Meeting messages table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS meeting_messages (
        id SERIAL PRIMARY KEY,
        meeting_id INTEGER REFERENCES meetings(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        message_type VARCHAR(20) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Meeting schedules table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS meeting_schedules (
        id SERIAL PRIMARY KEY,
        meeting_id INTEGER REFERENCES meetings(id) ON DELETE CASCADE,
        creator_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(200) NOT NULL,
        description TEXT,
        location VARCHAR(200),
        schedule_date TIMESTAMP NOT NULL,
        max_participants INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Meeting schedule participants table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS meeting_schedule_participants (
        id SERIAL PRIMARY KEY,
        schedule_id INTEGER REFERENCES meeting_schedules(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(schedule_id, user_id)
      )
    `);

    // Meeting boards table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS meeting_boards (
        id SERIAL PRIMARY KEY,
        meeting_id INTEGER REFERENCES meetings(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL,
        created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(meeting_id, name)
      )
    `);

    // Meeting posts table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS meeting_posts (
        id SERIAL PRIMARY KEY,
        meeting_id INTEGER REFERENCES meetings(id) ON DELETE CASCADE,
        author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        board_name VARCHAR(100) NOT NULL DEFAULT '자유 게시판',
        content TEXT NOT NULL,
        images TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Meeting post likes table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS meeting_post_likes (
        id SERIAL PRIMARY KEY,
        post_id INTEGER REFERENCES meeting_posts(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(post_id, user_id)
      )
    `);

    // Meeting post comments table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS meeting_post_comments (
        id SERIAL PRIMARY KEY,
        post_id INTEGER REFERENCES meeting_posts(id) ON DELETE CASCADE,
        author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // UsedItems (중고거래) table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS used_items (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        price INTEGER NOT NULL DEFAULT 0,
        is_negotiable BOOLEAN DEFAULT FALSE,
        images TEXT[],
        category VARCHAR(50) NOT NULL,
        condition VARCHAR(50) NOT NULL,
        status VARCHAR(20) DEFAULT 'available',
        location VARCHAR(100),
        author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        view_count INTEGER DEFAULT 0,
        chat_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        bumped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // UsedItem likes table (관심상품용)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS used_item_likes (
        id SERIAL PRIMARY KEY,
        item_id INTEGER REFERENCES used_items(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(item_id, user_id)
      )
    `);

    // Direct chats table (중고거래 1:1 채팅)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS direct_chats (
        id SERIAL PRIMARY KEY,
        used_item_id INTEGER REFERENCES used_items(id) ON DELETE CASCADE,
        buyer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        seller_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(used_item_id, buyer_id)
      )
    `);

    // Direct messages table (1:1 채팅 메시지)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS direct_messages (
        id SERIAL PRIMARY KEY,
        chat_id INTEGER REFERENCES direct_chats(id) ON DELETE CASCADE,
        sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Insert default notice if none exists
    const noticeCheck = await pool.query('SELECT COUNT(*) FROM notices');
    if (parseInt(noticeCheck.rows[0].count) === 0) {
      await pool.query(
        'INSERT INTO notices (title, content) VALUES ($1, $2)',
        ['약통 서비스 오픈!', '약사 커뮤니티 약통이 오픈했습니다. 많은 이용 부탁드립니다.']
      );
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Auth middleware
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: '인증이 필요합니다.' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: '유효하지 않은 토큰입니다.' });
    }
    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(401).json({ message: '토큰이 만료되었습니다.' });
  }
};

// ==================== Auth API ====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ message: '모든 필드를 입력해주세요.' });
    }

    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: '이미 등록된 이메일입니다.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userCount = await pool.query('SELECT COUNT(*) FROM users');
    const isAdmin = parseInt(userCount.rows[0].count) === 0;

    const result = await pool.query(
      `INSERT INTO users (email, password, name, is_admin)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [email, hashedPassword, name, isAdmin]
    );

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        profileImage: user.profile_image,
        isAdmin: user.is_admin,
        userType: user.user_type || 'general',
        reputationScore: user.reputation_score || 0,
        licenseStatus: user.license_status || 'none',
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다.' });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다.' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        profileImage: user.profile_image,
        isAdmin: user.is_admin,
        userType: user.user_type || 'general',
        reputationScore: user.reputation_score || 0,
        licenseStatus: user.license_status || 'none',
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 소셜 로그인
app.post('/api/auth/social', async (req, res) => {
  try {
    const { provider, accessToken, email, name, profileImage } = req.body;

    if (!provider || !accessToken) {
      return res.status(400).json({ message: 'provider와 accessToken이 필요합니다.' });
    }

    // TODO: 각 provider별 토큰 검증 (프로덕션에서는 필수)
    // 카카오: https://kapi.kakao.com/v2/user/me
    // 네이버: https://openapi.naver.com/v1/nid/me
    // 구글: https://oauth2.googleapis.com/tokeninfo?access_token=
    // 애플: JWT 토큰 검증

    // 이메일로 기존 사용자 확인
    let user;
    if (email) {
      const existingUser = await pool.query(
        'SELECT * FROM users WHERE email = $1',
        [email]
      );

      if (existingUser.rows.length > 0) {
        // 기존 사용자 로그인
        user = existingUser.rows[0];

        // 프로필 이미지 업데이트 (있는 경우)
        if (profileImage && !user.profile_image) {
          await pool.query(
            'UPDATE users SET profile_image = $1 WHERE id = $2',
            [profileImage, user.id]
          );
          user.profile_image = profileImage;
        }
      }
    }

    // 새 사용자 생성
    if (!user) {
      // 소셜 로그인은 랜덤 비밀번호 생성 (로그인에 사용 안함)
      const randomPassword = Math.random().toString(36).slice(-16);
      const hashedPassword = await bcrypt.hash(randomPassword, 10);

      // 닉네임 생성 (없으면 provider + 랜덤 숫자)
      const userName = name || `${provider}사용자${Math.floor(Math.random() * 10000)}`;
      const userEmail = email || `${provider}_${Date.now()}@social.yaktong.app`;

      const newUser = await pool.query(
        `INSERT INTO users (email, password, name, profile_image, is_admin, social_provider)
         VALUES ($1, $2, $3, $4, false, $5)
         RETURNING *`,
        [userEmail, hashedPassword, userName, profileImage, provider]
      );
      user = newUser.rows[0];
    }

    // JWT 토큰 생성
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        profileImage: user.profile_image,
        isAdmin: user.is_admin,
        userType: user.user_type || 'general',
        reputationScore: user.reputation_score || 0,
        licenseStatus: user.license_status || 'none',
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Social login error:', error);
    res.status(500).json({ message: '소셜 로그인 중 오류가 발생했습니다.' });
  }
});

// 현재 사용자 정보 조회
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, is_admin, profile_image, phone, user_type, reputation_score, license_status, created_at FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }

    const user = result.rows[0];
    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      isAdmin: user.is_admin,
      profileImage: user.profile_image,
      phone: user.phone,
      userType: user.user_type || 'general',
      reputationScore: user.reputation_score || 0,
      licenseStatus: user.license_status || 'none',
      createdAt: user.created_at
    });
  } catch (error) {
    console.error('Get me error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const isValidPassword = await bcrypt.compare(currentPassword, req.user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: '현재 비밀번호가 올바르지 않습니다.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, req.user.id]);

    res.json({ message: '비밀번호가 변경되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/auth/nickname', authMiddleware, async (req, res) => {
  try {
    const { nickname } = req.body;
    await pool.query('UPDATE users SET name = $1 WHERE id = $2', [nickname, req.user.id]);
    res.json({ message: '닉네임이 변경되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/auth/phone', authMiddleware, async (req, res) => {
  try {
    const { phone } = req.body;
    await pool.query('UPDATE users SET phone = $1 WHERE id = $2', [phone, req.user.id]);
    res.json({ message: '전화번호가 변경되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/auth/profile-image', authMiddleware, async (req, res) => {
  try {
    const { profileImage } = req.body;
    await pool.query('UPDATE users SET profile_image = $1 WHERE id = $2', [profileImage, req.user.id]);
    res.json({ message: '프로필 이미지가 변경되었습니다.', profileImage });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/auth/check-nickname', authMiddleware, async (req, res) => {
  try {
    const { nickname } = req.body;
    const result = await pool.query('SELECT id FROM users WHERE name = $1 AND id != $2', [nickname, req.user.id]);
    res.json({ available: result.rows.length === 0 });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/auth/delete-account', authMiddleware, async (req, res) => {
  try {
    const { password } = req.body;

    const isValidPassword = await bcrypt.compare(password, req.user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: '비밀번호가 올바르지 않습니다.' });
    }

    await pool.query('DELETE FROM users WHERE id = $1', [req.user.id]);
    res.json({ message: '계정이 삭제되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== License Verification API ====================

// 자격증 제출 (약사면허증 또는 약국개설등록증)
app.post('/api/auth/submit-license', authMiddleware, async (req, res) => {
  try {
    const { licenseType, licenseImage } = req.body;

    if (!['pharmacist', 'pharmacy_owner'].includes(licenseType)) {
      return res.status(400).json({ message: '올바른 자격 유형을 선택해주세요.' });
    }

    if (!licenseImage) {
      return res.status(400).json({ message: '자격증 이미지를 업로드해주세요.' });
    }

    // 이미 승인된 경우 체크
    if (req.user.user_type !== 'general') {
      return res.status(400).json({ message: '이미 자격이 인증되었습니다.' });
    }

    // 대기 중인 요청이 있는지 체크
    const pendingCheck = await pool.query(
      'SELECT id FROM license_verifications WHERE user_id = $1 AND status = $2',
      [req.user.id, 'pending']
    );
    if (pendingCheck.rows.length > 0) {
      return res.status(400).json({ message: '이미 심사 대기 중인 요청이 있습니다.' });
    }

    const result = await pool.query(
      `INSERT INTO license_verifications (user_id, request_type, license_image)
       VALUES ($1, $2, $3) RETURNING id`,
      [req.user.id, licenseType, licenseImage]
    );

    // users 테이블 상태 업데이트
    await pool.query(
      `UPDATE users SET license_status = 'pending' WHERE id = $1`,
      [req.user.id]
    );

    res.json({
      message: '자격 인증 요청이 제출되었습니다.',
      requestId: result.rows[0].id,
      status: 'pending'
    });
  } catch (error) {
    console.error('Submit license error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 내 자격 인증 상태 조회
app.get('/api/auth/license-status', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT lv.*, u.user_type, u.license_status
       FROM users u
       LEFT JOIN license_verifications lv ON u.id = lv.user_id
       WHERE u.id = $1
       ORDER BY lv.submitted_at DESC LIMIT 1`,
      [req.user.id]
    );

    const row = result.rows[0];
    res.json({
      userType: row?.user_type || 'general',
      licenseStatus: row?.license_status || 'none',
      lastRequest: row?.id ? {
        id: row.id,
        type: row.request_type,
        status: row.status,
        rejectionReason: row.rejection_reason,
        submittedAt: row.submitted_at,
        reviewedAt: row.reviewed_at
      } : null
    });
  } catch (error) {
    console.error('License status error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 관리자: 승인 대기 목록 조회
app.get('/api/admin/license-requests', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '권한이 없습니다.' });
    }

    const { status = 'pending' } = req.query;

    const result = await pool.query(
      `SELECT lv.*, u.name, u.email, u.profile_image
       FROM license_verifications lv
       JOIN users u ON lv.user_id = u.id
       WHERE lv.status = $1
       ORDER BY lv.submitted_at ASC`,
      [status]
    );

    res.json(result.rows.map(r => ({
      id: r.id,
      userId: r.user_id,
      userName: r.name,
      userEmail: r.email,
      userProfileImage: r.profile_image,
      requestType: r.request_type,
      licenseImage: r.license_image,
      status: r.status,
      submittedAt: r.submitted_at
    })));
  } catch (error) {
    console.error('Get license requests error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 관리자: 대기 목록 개수 조회
app.get('/api/admin/license-requests/count', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '권한이 없습니다.' });
    }

    const result = await pool.query(
      `SELECT COUNT(*) FROM license_verifications WHERE status = 'pending'`
    );

    res.json({ count: parseInt(result.rows[0].count) });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 관리자: 자격 승인
app.post('/api/admin/license-requests/:id/approve', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '권한이 없습니다.' });
    }

    const requestId = parseInt(req.params.id);

    // 요청 정보 조회
    const requestResult = await pool.query(
      'SELECT * FROM license_verifications WHERE id = $1',
      [requestId]
    );

    if (requestResult.rows.length === 0) {
      return res.status(404).json({ message: '요청을 찾을 수 없습니다.' });
    }

    const request = requestResult.rows[0];
    if (request.status !== 'pending') {
      return res.status(400).json({ message: '이미 처리된 요청입니다.' });
    }

    const newUserType = request.request_type;

    // 요청 상태 업데이트
    await pool.query(
      `UPDATE license_verifications
       SET status = 'approved', reviewer_id = $1, reviewed_at = NOW()
       WHERE id = $2`,
      [req.user.id, requestId]
    );

    // 사용자 유형 업데이트
    await pool.query(
      `UPDATE users SET user_type = $1, license_status = 'approved' WHERE id = $2`,
      [newUserType, request.user_id]
    );

    // 알림 생성
    const userTypeName = newUserType === 'pharmacist' ? '약사' : '개국약사';
    await pool.query(
      `INSERT INTO notifications (user_id, type, title, message)
       VALUES ($1, 'license_approved', '자격 인증 완료', $2)`,
      [request.user_id, `축하합니다! ${userTypeName} 자격이 인증되었습니다.`]
    );

    res.json({ message: '승인되었습니다.' });
  } catch (error) {
    console.error('Approve license error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 관리자: 자격 거부
app.post('/api/admin/license-requests/:id/reject', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '권한이 없습니다.' });
    }

    const requestId = parseInt(req.params.id);
    const { reason } = req.body;

    const requestResult = await pool.query(
      'SELECT * FROM license_verifications WHERE id = $1',
      [requestId]
    );

    if (requestResult.rows.length === 0) {
      return res.status(404).json({ message: '요청을 찾을 수 없습니다.' });
    }

    const request = requestResult.rows[0];
    if (request.status !== 'pending') {
      return res.status(400).json({ message: '이미 처리된 요청입니다.' });
    }

    await pool.query(
      `UPDATE license_verifications
       SET status = 'rejected', rejection_reason = $1, reviewer_id = $2, reviewed_at = NOW()
       WHERE id = $3`,
      [reason || '요청이 거부되었습니다.', req.user.id, requestId]
    );

    await pool.query(
      `UPDATE users SET license_status = 'rejected' WHERE id = $1`,
      [request.user_id]
    );

    // 알림 생성
    const rejectMessage = reason || '제출하신 서류를 확인해주세요.';
    await pool.query(
      `INSERT INTO notifications (user_id, type, title, message)
       VALUES ($1, 'license_rejected', '자격 인증 반려', $2)`,
      [request.user_id, `자격 인증이 반려되었습니다. 사유: ${rejectMessage}`]
    );

    res.json({ message: '거부되었습니다.' });
  } catch (error) {
    console.error('Reject license error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Reputation API ====================

// 인기도 투표
app.post('/api/reputation/vote', authMiddleware, async (req, res) => {
  try {
    const { targetId, voteType } = req.body;

    // 약사/개국약사만 투표 가능
    if (!['pharmacist', 'pharmacy_owner'].includes(req.user.user_type)) {
      return res.status(403).json({ message: '약사 또는 개국약사만 투표할 수 있습니다.' });
    }

    // voteType 검증
    if (![1, -1].includes(voteType)) {
      return res.status(400).json({ message: '올바른 투표 유형을 선택해주세요.' });
    }

    // 대상 사용자 조회
    const targetUser = await pool.query(
      'SELECT user_type FROM users WHERE id = $1',
      [targetId]
    );

    if (targetUser.rows.length === 0) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }

    // 대상도 약사/개국약사여야 함
    if (!['pharmacist', 'pharmacy_owner'].includes(targetUser.rows[0].user_type)) {
      return res.status(400).json({ message: '약사 또는 개국약사에게만 투표할 수 있습니다.' });
    }

    // 자기 자신에게 투표 불가
    if (req.user.id === targetId) {
      return res.status(400).json({ message: '자신에게는 투표할 수 없습니다.' });
    }

    // 오늘 이미 투표했는지 확인 (하루에 1명에게만)
    const todayVote = await pool.query(
      `SELECT id FROM reputation_votes
       WHERE voter_id = $1 AND DATE(created_at) = CURRENT_DATE`,
      [req.user.id]
    );

    if (todayVote.rows.length > 0) {
      return res.status(400).json({ message: '오늘은 이미 다른 사용자에게 투표하셨습니다.' });
    }

    // 30일 내 동일인에게 투표했는지 확인
    const recentVote = await pool.query(
      `SELECT id FROM reputation_votes
       WHERE voter_id = $1 AND target_id = $2
       AND created_at > NOW() - INTERVAL '30 days'`,
      [req.user.id, targetId]
    );

    if (recentVote.rows.length > 0) {
      return res.status(400).json({ message: '같은 사용자에게는 30일에 1번만 투표할 수 있습니다.' });
    }

    // 투표 기록
    await pool.query(
      'INSERT INTO reputation_votes (voter_id, target_id, vote_type) VALUES ($1, $2, $3)',
      [req.user.id, targetId, voteType]
    );

    // 대상 사용자 점수 업데이트
    await pool.query(
      'UPDATE users SET reputation_score = reputation_score + $1 WHERE id = $2',
      [voteType, targetId]
    );

    const newScore = await pool.query(
      'SELECT reputation_score FROM users WHERE id = $1',
      [targetId]
    );

    res.json({
      message: '투표가 완료되었습니다.',
      targetNewScore: newScore.rows[0].reputation_score
    });
  } catch (error) {
    console.error('Reputation vote error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 투표 가능 여부 확인
app.get('/api/reputation/can-vote/:targetId', authMiddleware, async (req, res) => {
  try {
    const targetId = parseInt(req.params.targetId);

    // 본인인지 확인
    if (req.user.id === targetId) {
      return res.json({ canVote: false, reason: 'self' });
    }

    // 투표자가 약사/개국약사인지 확인
    if (!['pharmacist', 'pharmacy_owner'].includes(req.user.user_type)) {
      return res.json({ canVote: false, reason: 'not_pharmacist' });
    }

    // 대상이 약사/개국약사인지 확인
    const targetUser = await pool.query(
      'SELECT user_type FROM users WHERE id = $1',
      [targetId]
    );

    if (targetUser.rows.length === 0) {
      return res.json({ canVote: false, reason: 'user_not_found' });
    }

    if (!['pharmacist', 'pharmacy_owner'].includes(targetUser.rows[0].user_type)) {
      return res.json({ canVote: false, reason: 'target_not_pharmacist' });
    }

    // 오늘 이미 투표했는지 확인
    const todayVote = await pool.query(
      `SELECT id FROM reputation_votes
       WHERE voter_id = $1 AND DATE(created_at) = CURRENT_DATE`,
      [req.user.id]
    );

    if (todayVote.rows.length > 0) {
      return res.json({ canVote: false, reason: 'daily_limit' });
    }

    // 30일 내 동일인에게 투표했는지 확인
    const recentVote = await pool.query(
      `SELECT id FROM reputation_votes
       WHERE voter_id = $1 AND target_id = $2
       AND created_at > NOW() - INTERVAL '30 days'`,
      [req.user.id, targetId]
    );

    if (recentVote.rows.length > 0) {
      return res.json({ canVote: false, reason: 'monthly_limit' });
    }

    res.json({ canVote: true });
  } catch (error) {
    console.error('Can vote check error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Post API ====================

app.get('/api/posts', authMiddleware, async (req, res) => {
  try {
    const { category, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    const isAdmin = req.user.is_admin;

    let query = 'SELECT p.*, u.name as real_author_name, u.profile_image as author_profile_image, u.user_type as author_user_type, u.reputation_score as author_reputation_score FROM posts p LEFT JOIN users u ON p.author_id = u.id';
    let params = [];

    if (category && category !== 'all') {
      query += ' WHERE p.category = $1';
      params.push(category);
    }

    query += ' ORDER BY p.created_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
    params.push(limit, offset);

    const result = await pool.query(query, params);

    const posts = result.rows.map(p => ({
      id: p.id,
      title: p.title,
      content: p.content,
      category: p.category,
      isAnonymous: p.is_anonymous,
      authorId: p.author_id,
      authorName: p.author_name,
      authorProfileImage: p.is_anonymous ? null : p.author_profile_image,
      authorUserType: p.is_anonymous ? null : p.author_user_type,
      authorReputationScore: p.is_anonymous ? null : p.author_reputation_score,
      realAuthorName: isAdmin && p.is_anonymous ? p.real_author_name : null,
      likeCount: p.like_count,
      commentCount: p.comment_count,
      viewCount: p.view_count,
      createdAt: p.created_at
    }));

    res.json({ posts });
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Static routes must come before parameterized routes
app.get('/api/posts/search', authMiddleware, async (req, res) => {
  try {
    const { q } = req.query;
    const result = await pool.query(
      "SELECT p.*, u.profile_image as author_profile_image FROM posts p LEFT JOIN users u ON p.author_id = u.id WHERE p.title ILIKE $1 OR p.content ILIKE $1 ORDER BY p.created_at DESC",
      [`%${q}%`]
    );

    const posts = result.rows.map(p => ({
      id: p.id,
      title: p.title,
      content: p.content,
      category: p.category,
      isAnonymous: p.is_anonymous,
      authorId: p.author_id,
      authorName: p.author_name,
      authorProfileImage: p.is_anonymous ? null : p.author_profile_image,
      likeCount: p.like_count,
      commentCount: p.comment_count,
      viewCount: p.view_count,
      createdAt: p.created_at
    }));

    res.json(posts);
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.get('/api/posts/my', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT p.*, u.profile_image as author_profile_image FROM posts p LEFT JOIN users u ON p.author_id = u.id WHERE p.author_id = $1 ORDER BY p.created_at DESC',
      [req.user.id]
    );

    const posts = result.rows.map(p => ({
      id: p.id,
      title: p.title,
      content: p.content,
      category: p.category,
      isAnonymous: p.is_anonymous,
      authorId: p.author_id,
      authorName: p.author_name,
      authorProfileImage: p.is_anonymous ? null : p.author_profile_image,
      likeCount: p.like_count,
      commentCount: p.comment_count,
      viewCount: p.view_count,
      createdAt: p.created_at
    }));

    res.json(posts);
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.get('/api/posts/my/comments', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM comments WHERE author_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );

    const comments = result.rows.map(c => ({
      id: c.id,
      postId: c.post_id,
      content: c.content,
      authorId: c.author_id,
      authorName: c.author_name,
      likeCount: c.like_count,
      createdAt: c.created_at
    }));

    res.json(comments);
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.get('/api/posts/my/likes', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.profile_image as author_profile_image FROM posts p
       INNER JOIN post_likes pl ON p.id = pl.post_id
       LEFT JOIN users u ON p.author_id = u.id
       WHERE pl.user_id = $1
       ORDER BY p.created_at DESC`,
      [req.user.id]
    );

    const posts = result.rows.map(p => ({
      id: p.id,
      title: p.title,
      content: p.content,
      category: p.category,
      isAnonymous: p.is_anonymous,
      authorId: p.author_id,
      authorName: p.author_name,
      authorProfileImage: p.is_anonymous ? null : p.author_profile_image,
      likeCount: p.like_count,
      commentCount: p.comment_count,
      viewCount: p.view_count,
      createdAt: p.created_at
    }));

    res.json(posts);
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Parameterized routes come after static routes
app.get('/api/posts/:id', authMiddleware, async (req, res) => {
  try {
    const postId = parseInt(req.params.id);
    const isAdmin = req.user.is_admin;

    await pool.query('UPDATE posts SET view_count = view_count + 1 WHERE id = $1', [postId]);

    const result = await pool.query(
      'SELECT p.*, u.name as real_author_name, u.profile_image as author_profile_image, u.user_type as author_user_type, u.reputation_score as author_reputation_score FROM posts p LEFT JOIN users u ON p.author_id = u.id WHERE p.id = $1',
      [postId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: '게시글을 찾을 수 없습니다.' });
    }

    const likeResult = await pool.query(
      'SELECT id FROM post_likes WHERE post_id = $1 AND user_id = $2',
      [postId, req.user.id]
    );

    const dislikeResult = await pool.query(
      'SELECT id FROM post_dislikes WHERE post_id = $1 AND user_id = $2',
      [postId, req.user.id]
    );

    const p = result.rows[0];
    res.json({
      id: p.id,
      title: p.title,
      content: p.content,
      category: p.category,
      isAnonymous: p.is_anonymous,
      authorId: p.author_id,
      authorName: p.author_name,
      authorProfileImage: p.is_anonymous ? null : p.author_profile_image,
      authorUserType: p.is_anonymous ? null : p.author_user_type,
      authorReputationScore: p.is_anonymous ? null : p.author_reputation_score,
      realAuthorName: isAdmin && p.is_anonymous ? p.real_author_name : null,
      images: p.images ? JSON.parse(p.images) : [],
      likeCount: p.like_count,
      dislikeCount: p.dislike_count || 0,
      commentCount: p.comment_count,
      viewCount: p.view_count,
      createdAt: p.created_at,
      isLiked: likeResult.rows.length > 0,
      isDisliked: dislikeResult.rows.length > 0
    });
  } catch (error) {
    console.error('Get post error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/posts', authMiddleware, async (req, res) => {
  try {
    const { title, content, category, isAnonymous, images } = req.body;
    const authorName = isAnonymous ? '익명' : req.user.name;

    // images 배열을 JSON 문자열로 변환
    const imagesJson = images && images.length > 0 ? JSON.stringify(images) : null;

    const result = await pool.query(
      'INSERT INTO posts (title, content, category, is_anonymous, author_id, author_name, images) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [title, content, category || 'daily', isAnonymous || false, req.user.id, authorName, imagesJson]
    );

    const p = result.rows[0];
    res.json({
      id: p.id,
      title: p.title,
      content: p.content,
      category: p.category,
      isAnonymous: p.is_anonymous,
      authorId: p.author_id,
      authorName: p.author_name,
      images: p.images ? JSON.parse(p.images) : [],
      likeCount: p.like_count,
      commentCount: p.comment_count,
      viewCount: p.view_count,
      createdAt: p.created_at
    });
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.delete('/api/posts/:id', authMiddleware, async (req, res) => {
  try {
    const postId = parseInt(req.params.id);
    await pool.query('DELETE FROM posts WHERE id = $1 AND author_id = $2', [postId, req.user.id]);
    res.json({ message: '게시글이 삭제되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/posts/:id/like', authMiddleware, async (req, res) => {
  try {
    const postId = parseInt(req.params.id);

    // Remove dislike if exists (can't like and dislike at same time)
    const existingDislike = await pool.query('SELECT id FROM post_dislikes WHERE post_id = $1 AND user_id = $2', [postId, req.user.id]);
    if (existingDislike.rows.length > 0) {
      await pool.query('DELETE FROM post_dislikes WHERE post_id = $1 AND user_id = $2', [postId, req.user.id]);
      await pool.query('UPDATE posts SET dislike_count = dislike_count - 1 WHERE id = $1', [postId]);
    }

    const existingLike = await pool.query(
      'SELECT id FROM post_likes WHERE post_id = $1 AND user_id = $2',
      [postId, req.user.id]
    );

    if (existingLike.rows.length > 0) {
      await pool.query('DELETE FROM post_likes WHERE post_id = $1 AND user_id = $2', [postId, req.user.id]);
      await pool.query('UPDATE posts SET like_count = like_count - 1 WHERE id = $1', [postId]);
      const result = await pool.query('SELECT like_count, dislike_count FROM posts WHERE id = $1', [postId]);
      res.json({ liked: false, likeCount: result.rows[0].like_count, dislikeCount: result.rows[0].dislike_count });
    } else {
      await pool.query('INSERT INTO post_likes (post_id, user_id) VALUES ($1, $2)', [postId, req.user.id]);
      await pool.query('UPDATE posts SET like_count = like_count + 1 WHERE id = $1', [postId]);
      const result = await pool.query('SELECT like_count, dislike_count, author_id, title FROM posts WHERE id = $1', [postId]);

      // 알림 생성 (자신의 글에 좋아요한 경우 제외)
      const postAuthorId = result.rows[0].author_id;
      if (postAuthorId && postAuthorId !== req.user.id) {
        await pool.query(
          `INSERT INTO notifications (user_id, type, title, message, post_id, from_user_id, from_user_name)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [postAuthorId, 'like', '새 좋아요', `${req.user.name}님이 "${result.rows[0].title}" 글을 좋아합니다.`, postId, req.user.id, req.user.name]
        );
      }

      res.json({ liked: true, likeCount: result.rows[0].like_count, dislikeCount: result.rows[0].dislike_count });
    }
  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/posts/:id/dislike', authMiddleware, async (req, res) => {
  try {
    const postId = parseInt(req.params.id);

    // Remove like if exists (can't like and dislike at same time)
    const existingLike = await pool.query('SELECT id FROM post_likes WHERE post_id = $1 AND user_id = $2', [postId, req.user.id]);
    if (existingLike.rows.length > 0) {
      await pool.query('DELETE FROM post_likes WHERE post_id = $1 AND user_id = $2', [postId, req.user.id]);
      await pool.query('UPDATE posts SET like_count = like_count - 1 WHERE id = $1', [postId]);
    }

    const existingDislike = await pool.query(
      'SELECT id FROM post_dislikes WHERE post_id = $1 AND user_id = $2',
      [postId, req.user.id]
    );

    if (existingDislike.rows.length > 0) {
      await pool.query('DELETE FROM post_dislikes WHERE post_id = $1 AND user_id = $2', [postId, req.user.id]);
      await pool.query('UPDATE posts SET dislike_count = dislike_count - 1 WHERE id = $1', [postId]);
      const result = await pool.query('SELECT like_count, dislike_count FROM posts WHERE id = $1', [postId]);
      res.json({ disliked: false, likeCount: result.rows[0].like_count, dislikeCount: result.rows[0].dislike_count });
    } else {
      await pool.query('INSERT INTO post_dislikes (post_id, user_id) VALUES ($1, $2)', [postId, req.user.id]);
      await pool.query('UPDATE posts SET dislike_count = dislike_count + 1 WHERE id = $1', [postId]);
      const result = await pool.query('SELECT like_count, dislike_count FROM posts WHERE id = $1', [postId]);
      res.json({ disliked: true, likeCount: result.rows[0].like_count, dislikeCount: result.rows[0].dislike_count });
    }
  } catch (error) {
    console.error('Dislike post error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Comment API ====================

app.get('/api/posts/:postId/comments', authMiddleware, async (req, res) => {
  try {
    const postId = parseInt(req.params.postId);
    const isAdmin = req.user.is_admin;

    // 게시글이 익명 게시판인지 확인
    const postResult = await pool.query('SELECT category FROM posts WHERE id = $1', [postId]);
    const isAnonymousBoard = postResult.rows[0]?.category === 'anonymous';

    const result = await pool.query(
      'SELECT c.*, u.name as real_author_name FROM comments c LEFT JOIN users u ON c.author_id = u.id WHERE c.post_id = $1 ORDER BY c.created_at ASC',
      [postId]
    );

    // Get like status for all comments
    const commentsWithLikes = await Promise.all(result.rows.map(async (c) => {
      const likeResult = await pool.query(
        'SELECT id FROM comment_likes WHERE comment_id = $1 AND user_id = $2',
        [c.id, req.user.id]
      );
      return {
        id: c.id,
        postId: c.post_id,
        parentId: c.parent_id,
        content: c.content,
        authorId: c.author_id,
        authorName: c.author_name,
        realAuthorName: isAdmin && isAnonymousBoard ? c.real_author_name : null,
        likeCount: c.like_count,
        createdAt: c.created_at,
        isLiked: likeResult.rows.length > 0,
        replies: []
      };
    }));

    // Build nested structure: parent comments with replies
    const commentMap = {};
    const rootComments = [];

    commentsWithLikes.forEach(c => {
      commentMap[c.id] = c;
    });

    commentsWithLikes.forEach(c => {
      if (c.parentId && commentMap[c.parentId]) {
        commentMap[c.parentId].replies.push(c);
      } else if (!c.parentId) {
        rootComments.push(c);
      }
    });

    res.json(rootComments);
  } catch (error) {
    console.error('Get comments error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/posts/:postId/comments', authMiddleware, async (req, res) => {
  try {
    const postId = parseInt(req.params.postId);
    const { content, parentId } = req.body;

    // 게시글 정보 조회
    const postResult = await pool.query('SELECT author_id, title, category FROM posts WHERE id = $1', [postId]);
    const post = postResult.rows[0];
    const isAnonymousBoard = post?.category === 'anonymous';
    const authorName = isAnonymousBoard ? '익명' : req.user.name;

    const result = await pool.query(
      'INSERT INTO comments (post_id, parent_id, content, author_id, author_name) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [postId, parentId || null, content, req.user.id, authorName]
    );

    await pool.query('UPDATE posts SET comment_count = comment_count + 1 WHERE id = $1', [postId]);

    const c = result.rows[0];

    // 알림 생성 (자신의 글에 자신이 댓글 단 경우 제외)
    if (parentId) {
      // 대댓글인 경우 - 원댓글 작성자에게 알림
      const parentComment = await pool.query('SELECT author_id FROM comments WHERE id = $1', [parentId]);
      const parentAuthorId = parentComment.rows[0]?.author_id;
      if (parentAuthorId && parentAuthorId !== req.user.id) {
        await pool.query(
          `INSERT INTO notifications (user_id, type, title, message, post_id, comment_id, from_user_id, from_user_name)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [parentAuthorId, 'reply', '새 답글', `${authorName}님이 회원님의 댓글에 답글을 남겼습니다.`, postId, c.id, req.user.id, authorName]
        );
      }
    } else {
      // 일반 댓글인 경우 - 게시글 작성자에게 알림
      if (post.author_id && post.author_id !== req.user.id) {
        await pool.query(
          `INSERT INTO notifications (user_id, type, title, message, post_id, comment_id, from_user_id, from_user_name)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [post.author_id, 'comment', '새 댓글', `${authorName}님이 "${post.title}" 글에 댓글을 남겼습니다.`, postId, c.id, req.user.id, authorName]
        );
      }
    }

    res.json({
      id: c.id,
      postId: c.post_id,
      parentId: c.parent_id,
      content: c.content,
      authorId: c.author_id,
      authorName: c.author_name,
      likeCount: c.like_count,
      createdAt: c.created_at,
      replies: []
    });
  } catch (error) {
    console.error('Create comment error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.delete('/api/comments/:id', authMiddleware, async (req, res) => {
  try {
    const commentId = parseInt(req.params.id);

    const comment = await pool.query('SELECT post_id FROM comments WHERE id = $1 AND author_id = $2', [commentId, req.user.id]);
    if (comment.rows.length > 0) {
      await pool.query('UPDATE posts SET comment_count = comment_count - 1 WHERE id = $1', [comment.rows[0].post_id]);
      await pool.query('DELETE FROM comments WHERE id = $1', [commentId]);
    }

    res.json({ message: '댓글이 삭제되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/comments/:id/like', authMiddleware, async (req, res) => {
  try {
    const commentId = parseInt(req.params.id);

    // Remove dislike if exists (can't like and dislike at same time)
    const existingDislike = await pool.query('SELECT id FROM comment_dislikes WHERE comment_id = $1 AND user_id = $2', [commentId, req.user.id]);
    if (existingDislike.rows.length > 0) {
      await pool.query('DELETE FROM comment_dislikes WHERE comment_id = $1 AND user_id = $2', [commentId, req.user.id]);
      await pool.query('UPDATE comments SET dislike_count = dislike_count - 1 WHERE id = $1', [commentId]);
    }

    const existingLike = await pool.query(
      'SELECT id FROM comment_likes WHERE comment_id = $1 AND user_id = $2',
      [commentId, req.user.id]
    );

    if (existingLike.rows.length > 0) {
      await pool.query('DELETE FROM comment_likes WHERE comment_id = $1 AND user_id = $2', [commentId, req.user.id]);
      await pool.query('UPDATE comments SET like_count = like_count - 1 WHERE id = $1', [commentId]);
      const result = await pool.query('SELECT like_count, dislike_count FROM comments WHERE id = $1', [commentId]);
      res.json({ liked: false, likeCount: result.rows[0].like_count, dislikeCount: result.rows[0].dislike_count });
    } else {
      await pool.query('INSERT INTO comment_likes (comment_id, user_id) VALUES ($1, $2)', [commentId, req.user.id]);
      await pool.query('UPDATE comments SET like_count = like_count + 1 WHERE id = $1', [commentId]);
      const result = await pool.query('SELECT like_count, dislike_count FROM comments WHERE id = $1', [commentId]);
      res.json({ liked: true, likeCount: result.rows[0].like_count, dislikeCount: result.rows[0].dislike_count });
    }
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/comments/:id/dislike', authMiddleware, async (req, res) => {
  try {
    const commentId = parseInt(req.params.id);

    // Remove like if exists (can't like and dislike at same time)
    const existingLike = await pool.query('SELECT id FROM comment_likes WHERE comment_id = $1 AND user_id = $2', [commentId, req.user.id]);
    if (existingLike.rows.length > 0) {
      await pool.query('DELETE FROM comment_likes WHERE comment_id = $1 AND user_id = $2', [commentId, req.user.id]);
      await pool.query('UPDATE comments SET like_count = like_count - 1 WHERE id = $1', [commentId]);
    }

    const existingDislike = await pool.query(
      'SELECT id FROM comment_dislikes WHERE comment_id = $1 AND user_id = $2',
      [commentId, req.user.id]
    );

    if (existingDislike.rows.length > 0) {
      await pool.query('DELETE FROM comment_dislikes WHERE comment_id = $1 AND user_id = $2', [commentId, req.user.id]);
      await pool.query('UPDATE comments SET dislike_count = dislike_count - 1 WHERE id = $1', [commentId]);
      const result = await pool.query('SELECT like_count, dislike_count FROM comments WHERE id = $1', [commentId]);
      res.json({ disliked: false, likeCount: result.rows[0].like_count, dislikeCount: result.rows[0].dislike_count });
    } else {
      await pool.query('INSERT INTO comment_dislikes (comment_id, user_id) VALUES ($1, $2)', [commentId, req.user.id]);
      await pool.query('UPDATE comments SET dislike_count = dislike_count + 1 WHERE id = $1', [commentId]);
      const result = await pool.query('SELECT like_count, dislike_count FROM comments WHERE id = $1', [commentId]);
      res.json({ disliked: true, likeCount: result.rows[0].like_count, dislikeCount: result.rows[0].dislike_count });
    }
  } catch (error) {
    console.error('Comment dislike error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== AI API (수정본) ====================

app.post('/api/ai/chat', authMiddleware, async (req, res) => {
  try {
    const userMessageRaw = String(req.body?.message ?? "").trim();
    if (!userMessageRaw) {
      return res.status(400).json({ error: "message is required" });
    }

    // 붙여쓴 질문 정규화 (검색 정확도 향상)
    const userMessage = userMessageRaw.replace(/(정|캡슐|주사|시럽)(성분|효능|용법|금기|상호작용)/g, '$1 $2');

    const sessionId = req.body?.sessionId || `session_${req.user.id}_${Date.now()}`;

    // 세션 가져오기 (TTL 적용)
    const session = getSession(sessionId);

    // user turn 추가
    pushTurn(session, {
      role: "user",
      parts: [{ text: userMessage }]
    });

    // generateContent 호출 (타임아웃 + 재시도 적용)
    const result = await generateWithRetry({
      model: "gemini-2.5-flash",
      contents: session.history,
      config: {
        temperature: 0.3,
        systemInstruction: AI_SYSTEM_PROMPT,
        tools: [{
          fileSearch: {
            fileSearchStoreNames: [ABS_STORE, REL_STORE]
          }
        }],
      },
    });

    const candidate = result?.candidates?.[0];

    // model turn을 history에 추가
    if (candidate?.content) {
      pushTurn(session, candidate.content);
    }

    // 근거 확인 (citations 있는지 체크)
    const hasCitations =
      !!candidate?.groundingMetadata ||
      !!candidate?.citationMetadata ||
      JSON.stringify(result).toLowerCase().includes("citation");

    // 응답 텍스트 추출 (parts 전체 결합)
    const responseText = extractText(result);

    // 빈 응답 처리
    if (!responseText) {
      console.warn("Empty model text", {
        finishReason: candidate?.finishReason,
        hasGrounding: !!candidate?.groundingMetadata,
      });
      return res.status(200).json({
        response: "현재 요청에서 텍스트 응답이 생성되지 않았습니다. 질문을 조금 더 구체화해 주세요.",
        sessionId,
        hasCitations: false,
      });
    }

    res.json({
      response: responseText,
      sessionId,
      hasCitations
    });

  } catch (error) {
    console.error('AI Chat Error:', error?.message || error, {
      status: error?.status,
      code: error?.code,
    });

    const isTimeout = error?.message === "AI_TIMEOUT";
    res.status(isTimeout ? 504 : 500).json({
      response: isTimeout
        ? '응답 시간이 초과되었습니다. 잠시 후 다시 시도해주세요.'
        : '죄송합니다. AI 서비스에 일시적인 문제가 발생했습니다.',
      error: error?.message
    });
  }
});

// ==================== Notice API ====================

app.get('/api/notices', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notices ORDER BY is_pinned DESC, created_at DESC');
    const notices = result.rows.map(n => ({
      id: n.id,
      title: n.title,
      content: n.content,
      authorId: n.author_id,
      authorName: n.author_name || '관리자',
      isPinned: n.is_pinned || false,
      createdAt: n.created_at
    }));
    res.json(notices);
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.get('/api/notices/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notices WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: '공지사항을 찾을 수 없습니다.' });
    }
    const n = result.rows[0];
    res.json({
      id: n.id,
      title: n.title,
      content: n.content,
      authorId: n.author_id,
      authorName: n.author_name || '관리자',
      isPinned: n.is_pinned || false,
      createdAt: n.created_at
    });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/notices', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '관리자만 공지사항을 작성할 수 있습니다.' });
    }

    const { title, content, isPinned } = req.body;

    if (!title || !content) {
      return res.status(400).json({ message: '제목과 내용을 입력해주세요.' });
    }

    const result = await pool.query(
      'INSERT INTO notices (title, content, author_id, author_name, is_pinned) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [title, content, req.user.id, req.user.name, isPinned || false]
    );

    const n = result.rows[0];
    res.json({
      id: n.id,
      title: n.title,
      content: n.content,
      authorId: n.author_id,
      authorName: n.author_name,
      isPinned: n.is_pinned,
      createdAt: n.created_at
    });
  } catch (error) {
    console.error('Create notice error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.put('/api/notices/:id', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '관리자만 공지사항을 수정할 수 있습니다.' });
    }

    const { title, content, isPinned } = req.body;
    const noticeId = parseInt(req.params.id);

    const result = await pool.query(
      `UPDATE notices
       SET title = $1, content = $2, is_pinned = $3, updated_at = NOW()
       WHERE id = $4
       RETURNING *`,
      [title, content, isPinned || false, noticeId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '공지사항을 찾을 수 없습니다.' });
    }

    const notice = result.rows[0];
    res.json({
      id: notice.id,
      title: notice.title,
      content: notice.content,
      authorId: notice.author_id,
      authorName: req.user.name,
      isPinned: notice.is_pinned,
      createdAt: notice.created_at,
      updatedAt: notice.updated_at,
    });
  } catch (error) {
    console.error('Update notice error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.delete('/api/notices/:id', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '관리자만 공지사항을 삭제할 수 있습니다.' });
    }

    await pool.query('DELETE FROM notices WHERE id = $1', [req.params.id]);
    res.json({ message: '공지사항이 삭제되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Notification API ====================

// 알림 목록 조회
app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
      [req.user.id]
    );

    const notifications = result.rows.map(n => ({
      id: n.id,
      type: n.type,
      title: n.title,
      message: n.message,
      postId: n.post_id,
      commentId: n.comment_id,
      fromUserId: n.from_user_id,
      fromUserName: n.from_user_name,
      isRead: n.is_read,
      createdAt: n.created_at
    }));

    res.json(notifications);
  } catch (error) {
    console.error('Get notifications error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 읽지 않은 알림 개수
app.get('/api/notifications/unread-count', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = FALSE',
      [req.user.id]
    );
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 알림 읽음 처리
app.post('/api/notifications/:id/read', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    res.json({ message: '알림을 읽음 처리했습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 모든 알림 읽음 처리
app.post('/api/notifications/read-all', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'UPDATE notifications SET is_read = TRUE WHERE user_id = $1',
      [req.user.id]
    );
    res.json({ message: '모든 알림을 읽음 처리했습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 알림 삭제
app.delete('/api/notifications/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM notifications WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    res.json({ message: '알림이 삭제되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 모든 알림 삭제
app.delete('/api/notifications', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM notifications WHERE user_id = $1', [req.user.id]);
    res.json({ message: '모든 알림이 삭제되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Job API ====================

// Haversine 거리 계산 (km)
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // 지구 반지름 (km)
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// 구인구직 목록 조회
app.get('/api/jobs', authMiddleware, async (req, res) => {
  try {
    const { type, category, workType, region, sort = 'recommended', salaryType, salaryMin, salaryMax, latitude, longitude, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    const userLat = Number(latitude);
    const userLon = Number(longitude);
    const hasUserLocation = Number.isFinite(userLat) && Number.isFinite(userLon);

    console.log('User location:', { latitude, longitude, userLat, userLon, hasUserLocation });

    let query = `
      SELECT j.*,
        EXISTS(SELECT 1 FROM job_likes WHERE job_id = j.id AND user_id = $1) as is_liked,
        (SELECT COUNT(*) FROM job_likes WHERE job_id = j.id) as like_count
      FROM jobs j WHERE 1=1
    `;
    const params = [req.user.id];
    let paramIndex = 2;

    if (type && type !== 'all') {
      query += ` AND j.type = $${paramIndex}`;
      params.push(type);
      paramIndex++;
    }

    if (category && category !== 'all') {
      query += ` AND j.category = $${paramIndex}`;
      params.push(category);
      paramIndex++;
    }

    if (workType && workType !== 'all') {
      query += ` AND j.work_type = $${paramIndex}`;
      params.push(workType);
      paramIndex++;
    }

    if (region && region !== 'all') {
      // 지역명 매핑 (짧은 이름 -> 긴 이름)
      const regionFullNames = {
        '서울': '서울특별시',
        '부산': '부산광역시',
        '대구': '대구광역시',
        '인천': '인천광역시',
        '광주': '광주광역시',
        '대전': '대전광역시',
        '울산': '울산광역시',
        '세종': '세종특별자치시',
        '경기': '경기도',
        '강원': '강원도',
        '충북': '충청북도',
        '충남': '충청남도',
        '전북': '전라북도',
        '전남': '전라남도',
        '경북': '경상북도',
        '경남': '경상남도',
        '제주': '제주특별자치도'
      };

      // "서울 종로구" 같은 형태면 메인/서브 지역 분리
      const regionParts = region.split(' ');
      const shortName = regionParts[0];
      const fullName = regionFullNames[shortName] || shortName;

      if (regionParts.length > 1 && regionParts[1] !== '전체') {
        // 서브 지역(구/군)으로 필터링 - location은 짧은/긴 이름 둘 다, address에서 구/군 검색
        query += ` AND (j.location IN ($${paramIndex}, $${paramIndex + 1}) AND j.address LIKE $${paramIndex + 2})`;
        params.push(shortName, fullName, `%${regionParts[1]}%`);
        paramIndex += 3;
      } else {
        // 메인 지역만 필터링 - 짧은/긴 이름 둘 다 매칭
        query += ` AND j.location IN ($${paramIndex}, $${paramIndex + 1})`;
        params.push(shortName, fullName);
        paramIndex += 2;
      }
    }

    // 급여 유형 필터 (시급/월급)
    if (salaryType && salaryType !== 'all') {
      query += ` AND j.salary_type = $${paramIndex}`;
      params.push(salaryType);
      paramIndex++;
    }

    // 급여 범위 필터
    if (salaryMin) {
      const minValue = Number(salaryMin);
      if (Number.isFinite(minValue)) {
        query += ` AND COALESCE(j.salary_max, j.salary_min) >= $${paramIndex}`;
        params.push(minValue);
        paramIndex++;
      }
    }
    if (salaryMax) {
      const maxValue = Number(salaryMax);
      if (Number.isFinite(maxValue)) {
        query += ` AND COALESCE(j.salary_min, j.salary_max) <= $${paramIndex}`;
        params.push(maxValue);
        paramIndex++;
      }
    }

    // 정렬 옵션: recommended(추천순), nearest(가까운순), popular(인기도순), latest(최신순), salaryDesc(높은급여순)
    let orderBy;
    switch (sort) {
      case 'nearest':
        // 가까운순은 일단 기본 정렬, 클라이언트에서 계산한 거리로 재정렬
        orderBy = 'COALESCE(j.bumped_at, j.created_at) DESC';
        break;
      case 'popular':
        orderBy = 'like_count DESC, j.view_count DESC';
        break;
      case 'latest':
        orderBy = 'j.created_at DESC';
        break;
      case 'salaryDesc':
        // 높은급여순: salary_max가 있으면 salary_max, 없으면 salary_min 기준 내림차순
        orderBy = 'COALESCE(j.salary_max, j.salary_min, 0) DESC';
        break;
      case 'recommended':
      default:
        // 추천순: 끌어올리기 시간 우선, 없으면 생성 시간
        orderBy = 'COALESCE(j.bumped_at, j.created_at) DESC';
        break;
    }
    query += ` ORDER BY j.is_premium DESC, ${orderBy} LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    let jobs = result.rows.map(j => {
      // 거리 계산
      let distance = null;
      const jobLat = Number(j.latitude);
      const jobLon = Number(j.longitude);
      const hasJobLocation = Number.isFinite(jobLat) && Number.isFinite(jobLon);

      if (hasUserLocation && hasJobLocation) {
        distance = calculateDistance(userLat, userLon, jobLat, jobLon);
      }

      return {
        id: j.id,
        title: j.title,
        type: j.type,
        workType: j.work_type,
        category: j.category,
        location: j.location,
        address: j.address,
        latitude: j.latitude ? parseFloat(j.latitude) : null,
        longitude: j.longitude ? parseFloat(j.longitude) : null,
        distance: distance,
        workDays: j.work_days,
        workHours: j.work_hours,
        salaryMin: j.salary_min,
        salaryMax: j.salary_max,
        salaryNegotiable: j.salary_negotiable,
        salaryType: j.salary_type || '월급',
        isAfterTax: j.is_after_tax,
        software: j.software,
        dispenser: j.dispenser,
        automation: j.automation,
        pharmacistCount: j.pharmacist_count,
        staffCount: j.staff_count,
        benefits: j.benefits,
        description: j.description,
        contactPhone: j.contact_phone,
        authorId: j.author_id,
        authorName: j.author_name,
        viewCount: j.view_count,
        applyCount: j.apply_count,
        likeCount: parseInt(j.like_count) || 0,
        isLiked: j.is_liked,
        isPremium: j.is_premium,
        isCompleted: j.is_completed || false,
        createdAt: j.created_at,
        bumpedAt: j.bumped_at
      };
    });

    // 가까운순 정렬 (거리가 있는 경우)
    if (sort === 'nearest' && hasUserLocation) {
      jobs.sort((a, b) => {
        // 프리미엄 우선
        if (a.isPremium !== b.isPremium) return b.isPremium ? 1 : -1;
        // 거리순
        if (a.distance === null) return 1;
        if (b.distance === null) return -1;
        return a.distance - b.distance;
      });
    }

    res.json(jobs);
  } catch (error) {
    console.error('Get jobs error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 좋아요한 공고 목록 (관심공고) (MUST be before /api/jobs/:id)
app.get('/api/jobs/liked/list', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT j.*, true as is_liked
      FROM jobs j
      INNER JOIN job_likes jl ON j.id = jl.job_id
      WHERE jl.user_id = $1
      ORDER BY jl.created_at DESC
    `, [req.user.id]);

    const jobs = result.rows.map(j => ({
      id: j.id,
      title: j.title,
      type: j.type,
      workType: j.work_type,
      category: j.category,
      location: j.location,
      address: j.address,
      workDays: j.work_days,
      workHours: j.work_hours,
      salaryMin: j.salary_min,
      salaryMax: j.salary_max,
      salaryNegotiable: j.salary_negotiable,
      salaryType: j.salary_type || '월급',
      isAfterTax: j.is_after_tax,
      viewCount: j.view_count,
      applyCount: j.apply_count,
      isLiked: true,
      isPremium: j.is_premium,
      isCompleted: j.is_completed || false,
      createdAt: j.created_at,
      bumpedAt: j.bumped_at
    }));

    res.json(jobs);
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 구인구직 상세 조회
app.get('/api/jobs/:id', authMiddleware, async (req, res) => {
  try {
    const jobId = parseInt(req.params.id);

    // 조회수 증가
    await pool.query('UPDATE jobs SET view_count = view_count + 1 WHERE id = $1', [jobId]);

    const result = await pool.query(`
      SELECT j.*,
        EXISTS(SELECT 1 FROM job_likes WHERE job_id = j.id AND user_id = $1) as is_liked,
        u.user_type as author_user_type,
        u.reputation_score as author_reputation_score,
        u.profile_image as author_profile_image
      FROM jobs j
      LEFT JOIN users u ON j.author_id = u.id
      WHERE j.id = $2
    `, [req.user.id, jobId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '공고를 찾을 수 없습니다.' });
    }

    const j = result.rows[0];
    res.json({
      id: j.id,
      title: j.title,
      type: j.type,
      workType: j.work_type,
      category: j.category,
      location: j.location,
      address: j.address,
      latitude: j.latitude ? parseFloat(j.latitude) : null,
      longitude: j.longitude ? parseFloat(j.longitude) : null,
      workDays: j.work_days,
      workHours: j.work_hours,
      salaryMin: j.salary_min,
      salaryMax: j.salary_max,
      salaryNegotiable: j.salary_negotiable,
      salaryType: j.salary_type || '월급',
      isAfterTax: j.is_after_tax,
      software: j.software,
      dispenser: j.dispenser,
      automation: j.automation,
      pharmacistCount: j.pharmacist_count,
      staffCount: j.staff_count,
      benefits: j.benefits,
      description: j.description,
      contactPhone: j.contact_phone,
      authorId: j.author_id,
      authorName: j.author_name,
      authorUserType: j.author_user_type || 'general',
      authorReputationScore: j.author_reputation_score || 0,
      authorProfileImage: j.author_profile_image,
      viewCount: j.view_count,
      applyCount: j.apply_count,
      isLiked: j.is_liked,
      isPremium: j.is_premium,
      isCompleted: j.is_completed || false,
      createdAt: j.created_at,
      bumpedAt: j.bumped_at
    });
  } catch (error) {
    console.error('Get job error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 구인구직 등록
app.post('/api/jobs', authMiddleware, async (req, res) => {
  try {
    const {
      title, type, workType, category, location, address,
      latitude, longitude, workDays, workHours,
      salaryMin, salaryMax, salaryNegotiable, salaryType, isAfterTax,
      software, dispenser, automation,
      pharmacistCount, staffCount, benefits, description, contactPhone
    } = req.body;

    const result = await pool.query(`
      INSERT INTO jobs (
        title, type, work_type, category, location, address,
        latitude, longitude, work_days, work_hours,
        salary_min, salary_max, salary_negotiable, salary_type, is_after_tax,
        software, dispenser, automation,
        pharmacist_count, staff_count, benefits, description, contact_phone,
        author_id, author_name
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)
      RETURNING *
    `, [
      title, type || 'hiring', workType || '풀타임', category || '약국',
      location, address, latitude, longitude, workDays, workHours,
      salaryMin, salaryMax, salaryNegotiable || false, salaryType || '월급', isAfterTax || false,
      software, dispenser, automation,
      pharmacistCount, staffCount, benefits, description, contactPhone,
      req.user.id, req.user.name
    ]);

    const j = result.rows[0];
    res.json({
      id: j.id,
      title: j.title,
      type: j.type,
      workType: j.work_type,
      category: j.category,
      createdAt: j.created_at
    });
  } catch (error) {
    console.error('Create job error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 구인구직 수정
app.put('/api/jobs/:id', authMiddleware, async (req, res) => {
  try {
    const jobId = parseInt(req.params.id);
    const {
      title, workType, category, location, address,
      latitude, longitude, workDays, workHours,
      salaryMin, salaryMax, salaryNegotiable, isAfterTax,
      software, dispenser, automation,
      pharmacistCount, staffCount, benefits, description, contactPhone
    } = req.body;

    const result = await pool.query(`
      UPDATE jobs SET
        title = $1, work_type = $2, category = $3, location = $4, address = $5,
        latitude = $6, longitude = $7, work_days = $8, work_hours = $9,
        salary_min = $10, salary_max = $11, salary_negotiable = $12, is_after_tax = $13,
        software = $14, dispenser = $15, automation = $16,
        pharmacist_count = $17, staff_count = $18, benefits = $19, description = $20, contact_phone = $21
      WHERE id = $22 AND author_id = $23
      RETURNING *
    `, [
      title, workType, category, location, address,
      latitude, longitude, workDays, workHours,
      salaryMin, salaryMax, salaryNegotiable, isAfterTax,
      software, dispenser, automation,
      pharmacistCount, staffCount, benefits, description, contactPhone,
      jobId, req.user.id
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '공고를 찾을 수 없거나 권한이 없습니다.' });
    }

    res.json({ message: '공고가 수정되었습니다.' });
  } catch (error) {
    console.error('Update job error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 구인구직 삭제
app.delete('/api/jobs/:id', authMiddleware, async (req, res) => {
  try {
    const jobId = parseInt(req.params.id);
    await pool.query('DELETE FROM jobs WHERE id = $1 AND author_id = $2', [jobId, req.user.id]);
    res.json({ message: '공고가 삭제되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 좋아요 토글 (관심공고)
app.post('/api/jobs/:id/like', authMiddleware, async (req, res) => {
  try {
    const jobId = parseInt(req.params.id);

    const existing = await pool.query(
      'SELECT id FROM job_likes WHERE job_id = $1 AND user_id = $2',
      [jobId, req.user.id]
    );

    if (existing.rows.length > 0) {
      await pool.query('DELETE FROM job_likes WHERE job_id = $1 AND user_id = $2', [jobId, req.user.id]);
      res.json({ liked: false });
    } else {
      await pool.query('INSERT INTO job_likes (job_id, user_id) VALUES ($1, $2)', [jobId, req.user.id]);
      res.json({ liked: true });
    }
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 끌어올리기
app.post('/api/jobs/:id/bump', authMiddleware, async (req, res) => {
  try {
    const jobId = parseInt(req.params.id);
    await pool.query(
      'UPDATE jobs SET bumped_at = NOW() WHERE id = $1 AND author_id = $2',
      [jobId, req.user.id]
    );
    res.json({ message: '공고가 끌어올려졌습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 고용 완료 토글
app.post('/api/jobs/:id/complete', authMiddleware, async (req, res) => {
  try {
    const jobId = parseInt(req.params.id);
    const result = await pool.query(
      'UPDATE jobs SET is_completed = NOT is_completed WHERE id = $1 AND author_id = $2 RETURNING is_completed',
      [jobId, req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: '공고를 찾을 수 없습니다.' });
    }
    const isCompleted = result.rows[0].is_completed;
    res.json({
      message: isCompleted ? '고용완료로 변경되었습니다.' : '구인중으로 변경되었습니다.',
      isCompleted
    });
  } catch (error) {
    console.error('Toggle complete error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== User Profile API ====================

// 사용자 프로필 조회
app.get('/api/users/:id/profile', authMiddleware, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    // 사용자 기본 정보 조회
    const userResult = await pool.query(
      `SELECT id, name, email, profile_image, user_type, reputation_score, created_at
       FROM users WHERE id = $1`,
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }

    const user = userResult.rows[0];

    // 사용자의 게시글 조회수 합계
    const viewsResult = await pool.query(
      `SELECT COALESCE(SUM(view_count), 0) as total_views FROM posts WHERE author_id = $1`,
      [userId]
    );

    // 사용자의 게시글 수 (익명 제외)
    const postCountResult = await pool.query(
      `SELECT COUNT(*) as post_count FROM posts WHERE author_id = $1 AND is_anonymous = false`,
      [userId]
    );

    // 사용자의 댓글 수
    const commentCountResult = await pool.query(
      `SELECT COUNT(*) as comment_count FROM comments WHERE author_id = $1`,
      [userId]
    );

    // 사용자가 받은 공감 수 (게시글 좋아요 + 댓글 좋아요)
    const likesResult = await pool.query(
      `SELECT
        (SELECT COALESCE(SUM(like_count), 0) FROM posts WHERE author_id = $1) +
        (SELECT COALESCE(SUM(like_count), 0) FROM comments WHERE author_id = $1) as total_likes`,
      [userId]
    );

    // 사용자의 게시글 목록 (최근 20개, 익명 제외)
    const postsResult = await pool.query(
      `SELECT id, title, content, category, view_count, like_count, comment_count, created_at
       FROM posts WHERE author_id = $1 AND is_anonymous = false
       ORDER BY created_at DESC LIMIT 20`,
      [userId]
    );

    // 사용자가 댓글 단 게시글 목록 (최근 20개)
    const commentedPostsResult = await pool.query(
      `SELECT DISTINCT ON (p.id) p.id, p.title, p.content, p.category, p.view_count, p.like_count, p.comment_count, p.created_at,
              c.content as my_comment, c.created_at as comment_created_at
       FROM posts p
       INNER JOIN comments c ON p.id = c.post_id
       WHERE c.author_id = $1
       ORDER BY p.id, c.created_at DESC
       LIMIT 20`,
      [userId]
    );

    res.json({
      user: {
        id: user.id,
        name: user.name,
        profileImage: user.profile_image,
        userType: user.user_type || 'general',
        reputationScore: user.reputation_score || 0,
        createdAt: user.created_at
      },
      stats: {
        totalViews: parseInt(viewsResult.rows[0].total_views) || 0,
        postCount: parseInt(postCountResult.rows[0].post_count) + parseInt(commentCountResult.rows[0].comment_count) || 0,
        receivedLikes: parseInt(likesResult.rows[0].total_likes) || 0,
        // 증가량은 별도 테이블이 필요하므로 일단 0으로 설정
        viewsGrowth: 0,
        postGrowth: 0,
        likesGrowth: 0
      },
      posts: postsResult.rows.map(p => ({
        id: p.id,
        title: p.title,
        content: p.content,
        category: p.category,
        viewCount: p.view_count,
        likeCount: p.like_count,
        commentCount: p.comment_count,
        createdAt: p.created_at
      })),
      commentedPosts: commentedPostsResult.rows.map(p => ({
        id: p.id,
        title: p.title,
        content: p.content,
        category: p.category,
        viewCount: p.view_count,
        likeCount: p.like_count,
        commentCount: p.comment_count,
        createdAt: p.created_at,
        myComment: p.my_comment,
        commentCreatedAt: p.comment_created_at
      }))
    });
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 차단
app.post('/api/users/:id/block', authMiddleware, async (req, res) => {
  try {
    const blockedId = parseInt(req.params.id);
    const blockerId = req.user.id;

    if (blockedId === blockerId) {
      return res.status(400).json({ message: '자신을 차단할 수 없습니다.' });
    }

    // 이미 차단했는지 확인
    const existing = await pool.query(
      'SELECT id FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2',
      [blockerId, blockedId]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ message: '이미 차단한 사용자입니다.' });
    }

    await pool.query(
      'INSERT INTO blocked_users (blocker_id, blocked_id) VALUES ($1, $2)',
      [blockerId, blockedId]
    );

    res.json({ message: '사용자를 차단했습니다.', blocked: true });
  } catch (error) {
    console.error('Block user error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 차단 해제
app.delete('/api/users/:id/block', authMiddleware, async (req, res) => {
  try {
    const blockedId = parseInt(req.params.id);
    const blockerId = req.user.id;

    const result = await pool.query(
      'DELETE FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2 RETURNING id',
      [blockerId, blockedId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '차단한 사용자가 아닙니다.' });
    }

    res.json({ message: '차단이 해제되었습니다.', blocked: false });
  } catch (error) {
    console.error('Unblock user error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 차단한 사용자 목록 조회
app.get('/api/users/blocked', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.profile_image, u.user_type, u.reputation_score, bu.created_at as blocked_at
       FROM blocked_users bu
       JOIN users u ON bu.blocked_id = u.id
       WHERE bu.blocker_id = $1
       ORDER BY bu.created_at DESC`,
      [req.user.id]
    );

    const blockedUsers = result.rows.map(u => ({
      id: u.id,
      name: u.name,
      profileImage: u.profile_image,
      userType: u.user_type,
      reputationScore: u.reputation_score,
      blockedAt: u.blocked_at
    }));

    res.json(blockedUsers);
  } catch (error) {
    console.error('Get blocked users error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 특정 사용자 차단 여부 확인
app.get('/api/users/:id/blocked', authMiddleware, async (req, res) => {
  try {
    const blockedId = parseInt(req.params.id);
    const result = await pool.query(
      'SELECT id FROM blocked_users WHERE blocker_id = $1 AND blocked_id = $2',
      [req.user.id, blockedId]
    );

    res.json({ blocked: result.rows.length > 0 });
  } catch (error) {
    console.error('Check blocked error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Admin API ====================

app.get('/api/admin/users', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '권한이 없습니다.' });
    }

    const result = await pool.query('SELECT id, email, name, phone, is_admin, is_blocked, created_at FROM users ORDER BY created_at DESC');
    const users = result.rows.map(u => ({
      id: u.id,
      email: u.email,
      name: u.name,
      phone: u.phone,
      isAdmin: u.is_admin,
      isBlocked: u.is_blocked || false,
      createdAt: u.created_at
    }));

    res.json(users);
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 회원 차단/해제
app.post('/api/admin/users/:id/block', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '권한이 없습니다.' });
    }

    const userId = parseInt(req.params.id);
    const { blocked } = req.body;

    await pool.query('UPDATE users SET is_blocked = $1 WHERE id = $2', [blocked, userId]);
    res.json({ message: blocked ? '회원이 차단되었습니다.' : '차단이 해제되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 회원 삭제
app.delete('/api/admin/users/:id', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '권한이 없습니다.' });
    }

    const userId = parseInt(req.params.id);
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    res.json({ message: '회원이 삭제되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 관리자 권한 부여/해제
app.post('/api/admin/users/:id/admin', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '권한이 없습니다.' });
    }

    const userId = parseInt(req.params.id);
    const { isAdmin } = req.body;

    await pool.query('UPDATE users SET is_admin = $1 WHERE id = $2', [isAdmin, userId]);
    res.json({ message: isAdmin ? '관리자로 지정되었습니다.' : '관리자 권한이 해제되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Pharmacy (매물) API ====================

// 매물 목록 조회
app.get('/api/pharmacies', authMiddleware, async (req, res) => {
  try {
    const { transactionType, region, commercialArea, prescriptionRange, sort, latitude, longitude, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    const userLat = Number(latitude);
    const userLon = Number(longitude);
    const hasUserLocation = Number.isFinite(userLat) && Number.isFinite(userLon);

    let query = `
      SELECT p.*,
        EXISTS(SELECT 1 FROM pharmacy_likes WHERE pharmacy_id = p.id AND user_id = $1) as is_liked,
        (SELECT COUNT(*) FROM pharmacy_likes WHERE pharmacy_id = p.id) as like_count
      FROM pharmacies p WHERE 1=1
    `;
    const params = [req.user.id];
    let paramIndex = 2;

    // 거래유형 필터
    if (transactionType && transactionType !== 'all') {
      query += ` AND p.transaction_type = $${paramIndex}`;
      params.push(transactionType);
      paramIndex++;
    }

    // 지역 필터
    if (region && region !== 'all') {
      query += ` AND (p.region LIKE $${paramIndex} OR p.address LIKE $${paramIndex})`;
      params.push(`%${region}%`);
      paramIndex++;
    }

    // 상권 필터
    if (commercialArea && commercialArea !== 'all') {
      query += ` AND p.commercial_area = $${paramIndex}`;
      params.push(commercialArea);
      paramIndex++;
    }

    // 조제수입 필터
    if (prescriptionRange && prescriptionRange !== 'all') {
      switch (prescriptionRange) {
        case '500미만':
          query += ` AND p.monthly_prescription_max < 500`;
          break;
        case '500~1000':
          query += ` AND p.monthly_prescription_min >= 500 AND p.monthly_prescription_max <= 1000`;
          break;
        case '1000~1500':
          query += ` AND p.monthly_prescription_min >= 1000 AND p.monthly_prescription_max <= 1500`;
          break;
        case '1500~2000':
          query += ` AND p.monthly_prescription_min >= 1500 AND p.monthly_prescription_max <= 2000`;
          break;
        case '2000이상':
          query += ` AND p.monthly_prescription_min >= 2000`;
          break;
      }
    }

    // 정렬
    let orderBy = 'COALESCE(p.bumped_at, p.created_at) DESC';
    switch (sort) {
      case 'popular':
        orderBy = 'like_count DESC, p.view_count DESC';
        break;
      case 'latest':
        orderBy = 'p.created_at DESC';
        break;
      case 'nearest':
        orderBy = 'COALESCE(p.bumped_at, p.created_at) DESC';
        break;
    }

    query += ` ORDER BY p.is_premium DESC, ${orderBy} LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    const pharmacies = result.rows.map(p => {
      let distance = null;
      const pLat = Number(p.latitude);
      const pLon = Number(p.longitude);
      if (hasUserLocation && Number.isFinite(pLat) && Number.isFinite(pLon)) {
        const R = 6371;
        const dLat = (pLat - userLat) * Math.PI / 180;
        const dLon = (pLon - userLon) * Math.PI / 180;
        const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                  Math.cos(userLat * Math.PI / 180) * Math.cos(pLat * Math.PI / 180) *
                  Math.sin(dLon/2) * Math.sin(dLon/2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        distance = Math.round(R * c * 10) / 10;
      }

      return {
        id: p.id,
        title: p.title,
        transactionType: p.transaction_type,
        region: p.region,
        address: p.address,
        latitude: p.latitude ? parseFloat(p.latitude) : null,
        longitude: p.longitude ? parseFloat(p.longitude) : null,
        distance,
        commercialArea: p.commercial_area,
        area: p.area ? parseFloat(p.area) : null,
        supplyArea: p.supply_area ? parseFloat(p.supply_area) : null,
        managementCost: p.management_cost,
        pharmacyType: p.pharmacy_type,
        monthlyPrescriptionMin: p.monthly_prescription_min,
        monthlyPrescriptionMax: p.monthly_prescription_max,
        dailySales: p.daily_sales,
        deposit: p.deposit,
        monthlyRent: p.monthly_rent,
        premium: p.premium,
        consultingFee: p.consulting_fee,
        description: p.description,
        contactPhone: p.contact_phone,
        authorId: p.author_id,
        authorName: p.author_name,
        viewCount: p.view_count,
        likeCount: parseInt(p.like_count) || 0,
        isLiked: p.is_liked,
        isPremium: p.is_premium,
        isCompleted: p.is_completed || false,
        createdAt: p.created_at,
        bumpedAt: p.bumped_at
      };
    });

    // 가까운순 정렬
    if (sort === 'nearest' && hasUserLocation) {
      pharmacies.sort((a, b) => {
        if (a.isPremium !== b.isPremium) return b.isPremium ? 1 : -1;
        if (a.distance === null) return 1;
        if (b.distance === null) return -1;
        return a.distance - b.distance;
      });
    }

    res.json(pharmacies);
  } catch (error) {
    console.error('Get pharmacies error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 매물 상세 조회
app.get('/api/pharmacies/:id', authMiddleware, async (req, res) => {
  try {
    const pharmacyId = parseInt(req.params.id);

    // 조회수 증가
    await pool.query('UPDATE pharmacies SET view_count = view_count + 1 WHERE id = $1', [pharmacyId]);

    const result = await pool.query(`
      SELECT p.*,
        EXISTS(SELECT 1 FROM pharmacy_likes WHERE pharmacy_id = p.id AND user_id = $1) as is_liked,
        u.user_type as author_user_type,
        u.reputation_score as author_reputation_score,
        u.profile_image as author_profile_image
      FROM pharmacies p
      LEFT JOIN users u ON p.author_id = u.id
      WHERE p.id = $2
    `, [req.user.id, pharmacyId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '매물을 찾을 수 없습니다.' });
    }

    const p = result.rows[0];
    res.json({
      id: p.id,
      title: p.title,
      transactionType: p.transaction_type,
      region: p.region,
      address: p.address,
      latitude: p.latitude ? parseFloat(p.latitude) : null,
      longitude: p.longitude ? parseFloat(p.longitude) : null,
      commercialArea: p.commercial_area,
      area: p.area ? parseFloat(p.area) : null,
      supplyArea: p.supply_area ? parseFloat(p.supply_area) : null,
      managementCost: p.management_cost,
      pharmacyType: p.pharmacy_type,
      monthlyPrescriptionMin: p.monthly_prescription_min,
      monthlyPrescriptionMax: p.monthly_prescription_max,
      dailySales: p.daily_sales,
      deposit: p.deposit,
      monthlyRent: p.monthly_rent,
      premium: p.premium,
      consultingFee: p.consulting_fee,
      description: p.description,
      contactPhone: p.contact_phone,
      authorId: p.author_id,
      authorName: p.author_name,
      authorUserType: p.author_user_type || 'general',
      authorReputationScore: p.author_reputation_score || 0,
      authorProfileImage: p.author_profile_image,
      viewCount: p.view_count,
      isLiked: p.is_liked,
      isPremium: p.is_premium,
      isCompleted: p.is_completed || false,
      createdAt: p.created_at,
      bumpedAt: p.bumped_at
    });
  } catch (error) {
    console.error('Get pharmacy error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 매물 등록
app.post('/api/pharmacies', authMiddleware, async (req, res) => {
  try {
    const {
      title, transactionType, region, address, latitude, longitude,
      commercialArea, area, supplyArea, managementCost, pharmacyType,
      monthlyPrescriptionMin, monthlyPrescriptionMax, dailySales,
      deposit, monthlyRent, premium, consultingFee, description, contactPhone
    } = req.body;

    const result = await pool.query(
      `INSERT INTO pharmacies (
        title, transaction_type, region, address, latitude, longitude,
        commercial_area, area, supply_area, management_cost, pharmacy_type,
        monthly_prescription_min, monthly_prescription_max, daily_sales,
        deposit, monthly_rent, premium, consulting_fee, description, contact_phone,
        author_id, author_name
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
      RETURNING *`,
      [
        title, transactionType, region, address, latitude, longitude,
        commercialArea, area, supplyArea, managementCost, pharmacyType,
        monthlyPrescriptionMin, monthlyPrescriptionMax, dailySales,
        deposit, monthlyRent, premium, consultingFee, description, contactPhone,
        req.user.id, req.user.name
      ]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Create pharmacy error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 매물 수정
app.put('/api/pharmacies/:id', authMiddleware, async (req, res) => {
  try {
    const pharmacyId = parseInt(req.params.id);
    const {
      title, transactionType, region, address, latitude, longitude,
      commercialArea, area, supplyArea, managementCost, pharmacyType,
      monthlyPrescriptionMin, monthlyPrescriptionMax, dailySales,
      deposit, monthlyRent, premium, consultingFee, description, contactPhone
    } = req.body;

    await pool.query(
      `UPDATE pharmacies SET
        title = $1, transaction_type = $2, region = $3, address = $4,
        latitude = $5, longitude = $6, commercial_area = $7, area = $8,
        supply_area = $9, management_cost = $10, pharmacy_type = $11,
        monthly_prescription_min = $12, monthly_prescription_max = $13,
        daily_sales = $14, deposit = $15, monthly_rent = $16, premium = $17,
        consulting_fee = $18, description = $19, contact_phone = $20
      WHERE id = $21 AND author_id = $22`,
      [
        title, transactionType, region, address, latitude, longitude,
        commercialArea, area, supplyArea, managementCost, pharmacyType,
        monthlyPrescriptionMin, monthlyPrescriptionMax, dailySales,
        deposit, monthlyRent, premium, consultingFee, description, contactPhone,
        pharmacyId, req.user.id
      ]
    );

    res.json({ message: '매물이 수정되었습니다.' });
  } catch (error) {
    console.error('Update pharmacy error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 매물 삭제
app.delete('/api/pharmacies/:id', authMiddleware, async (req, res) => {
  try {
    const pharmacyId = parseInt(req.params.id);
    await pool.query('DELETE FROM pharmacies WHERE id = $1 AND author_id = $2', [pharmacyId, req.user.id]);
    res.json({ message: '매물이 삭제되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 매물 좋아요 토글
app.post('/api/pharmacies/:id/like', authMiddleware, async (req, res) => {
  try {
    const pharmacyId = parseInt(req.params.id);

    const existing = await pool.query(
      'SELECT id FROM pharmacy_likes WHERE pharmacy_id = $1 AND user_id = $2',
      [pharmacyId, req.user.id]
    );

    if (existing.rows.length > 0) {
      await pool.query('DELETE FROM pharmacy_likes WHERE pharmacy_id = $1 AND user_id = $2', [pharmacyId, req.user.id]);
      res.json({ liked: false });
    } else {
      await pool.query('INSERT INTO pharmacy_likes (pharmacy_id, user_id) VALUES ($1, $2)', [pharmacyId, req.user.id]);
      res.json({ liked: true });
    }
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 매물 끌어올리기
app.post('/api/pharmacies/:id/bump', authMiddleware, async (req, res) => {
  try {
    const pharmacyId = parseInt(req.params.id);
    await pool.query(
      'UPDATE pharmacies SET bumped_at = NOW() WHERE id = $1 AND author_id = $2',
      [pharmacyId, req.user.id]
    );
    res.json({ message: '매물이 끌어올려졌습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// 매물 거래완료 토글
app.post('/api/pharmacies/:id/complete', authMiddleware, async (req, res) => {
  try {
    const pharmacyId = parseInt(req.params.id);
    const result = await pool.query(
      'UPDATE pharmacies SET is_completed = NOT is_completed WHERE id = $1 AND author_id = $2 RETURNING is_completed',
      [pharmacyId, req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: '매물을 찾을 수 없습니다.' });
    }
    const isCompleted = result.rows[0].is_completed;
    res.json({
      message: isCompleted ? '거래완료로 변경되었습니다.' : '거래가능으로 변경되었습니다.',
      isCompleted
    });
  } catch (error) {
    console.error('Toggle complete error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Meetings API ====================

// Get all meetings
app.get('/api/meetings', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT m.*, u.name as author_name,
        EXISTS(SELECT 1 FROM meeting_members mm WHERE mm.meeting_id = m.id AND mm.user_id = $1) as is_joined,
        EXISTS(SELECT 1 FROM meeting_likes ml WHERE ml.meeting_id = m.id AND ml.user_id = $1) as is_liked
      FROM meetings m
      LEFT JOIN users u ON m.author_id = u.id
      ORDER BY m.created_at DESC
    `, [req.user.id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Get meetings error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Get single meeting
app.get('/api/meetings/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(`
      SELECT m.*, u.name as author_name,
        EXISTS(SELECT 1 FROM meeting_members mm WHERE mm.meeting_id = m.id AND mm.user_id = $1) as is_joined,
        EXISTS(SELECT 1 FROM meeting_likes ml WHERE ml.meeting_id = m.id AND ml.user_id = $1) as is_liked
      FROM meetings m
      LEFT JOIN users u ON m.author_id = u.id
      WHERE m.id = $2
    `, [req.user.id, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '모임을 찾을 수 없습니다.' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get meeting error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Create meeting
app.post('/api/meetings', authMiddleware, async (req, res) => {
  try {
    const { title, description, category, location, image_base64 } = req.body;

    const result = await pool.query(
      `INSERT INTO meetings (title, description, category, location, image_base64, author_id)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [title, description || '', category, location, image_base64, req.user.id]
    );

    const meetingId = result.rows[0].id;

    // Add creator as host member
    await pool.query(
      `INSERT INTO meeting_members (meeting_id, user_id, is_host) VALUES ($1, $2, TRUE)`,
      [meetingId, req.user.id]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Create meeting error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Update meeting
app.put('/api/meetings/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, category, location, image_base64, status } = req.body;

    const result = await pool.query(
      `UPDATE meetings
       SET title = COALESCE($1, title),
           description = COALESCE($2, description),
           category = COALESCE($3, category),
           location = COALESCE($4, location),
           image_base64 = COALESCE($5, image_base64),
           status = COALESCE($6, status)
       WHERE id = $7 AND author_id = $8 RETURNING *`,
      [title, description, category, location, image_base64, status, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '모임을 찾을 수 없거나 수정 권한이 없습니다.' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update meeting error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Delete meeting
app.delete('/api/meetings/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'DELETE FROM meetings WHERE id = $1 AND author_id = $2 RETURNING id',
      [id, req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: '모임을 찾을 수 없거나 삭제 권한이 없습니다.' });
    }
    res.json({ message: '모임이 삭제되었습니다.' });
  } catch (error) {
    console.error('Delete meeting error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Join meeting (request to join - pending approval)
app.post('/api/meetings/:id/join', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if already joined or pending
    const existing = await pool.query(
      'SELECT id, status FROM meeting_members WHERE meeting_id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (existing.rows.length > 0) {
      const status = existing.rows[0].status;
      if (status === 'approved') {
        return res.status(400).json({ message: '이미 가입한 모임입니다.' });
      } else if (status === 'pending') {
        return res.status(400).json({ message: '가입 승인 대기 중입니다.' });
      } else if (status === 'rejected') {
        // Allow re-request after rejection
        await pool.query(
          'UPDATE meeting_members SET status = $1 WHERE meeting_id = $2 AND user_id = $3',
          ['pending', id, req.user.id]
        );
        return res.json({ message: '가입 신청이 완료되었습니다. 모임장의 승인을 기다려주세요.' });
      }
    }

    // Insert as pending
    await pool.query(
      'INSERT INTO meeting_members (meeting_id, user_id, status) VALUES ($1, $2, $3)',
      [id, req.user.id, 'pending']
    );

    res.json({ message: '가입 신청이 완료되었습니다. 모임장의 승인을 기다려주세요.' });
  } catch (error) {
    console.error('Join meeting error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Get pending join requests (host only)
app.get('/api/meetings/:id/requests', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if user is host
    const hostCheck = await pool.query(
      'SELECT id FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND is_host = true',
      [id, req.user.id]
    );
    if (hostCheck.rows.length === 0) {
      return res.status(403).json({ message: '모임장만 가입 신청을 확인할 수 있습니다.' });
    }

    const result = await pool.query(`
      SELECT mm.*, u.name, u.profile_image, u.email
      FROM meeting_members mm
      JOIN users u ON mm.user_id = u.id
      WHERE mm.meeting_id = $1 AND mm.status = 'pending'
      ORDER BY mm.joined_at DESC
    `, [id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get join requests error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Approve join request (host only)
app.post('/api/meetings/:id/approve/:userId', authMiddleware, async (req, res) => {
  try {
    const { id, userId } = req.params;

    // Check if user is host
    const hostCheck = await pool.query(
      'SELECT id FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND is_host = true',
      [id, req.user.id]
    );
    if (hostCheck.rows.length === 0) {
      return res.status(403).json({ message: '모임장만 가입을 승인할 수 있습니다.' });
    }

    // Update status to approved
    const result = await pool.query(
      'UPDATE meeting_members SET status = $1, joined_at = NOW() WHERE meeting_id = $2 AND user_id = $3 AND status = $4 RETURNING id',
      ['approved', id, userId, 'pending']
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '가입 신청을 찾을 수 없습니다.' });
    }

    // Update member count
    await pool.query(
      'UPDATE meetings SET member_count = member_count + 1 WHERE id = $1',
      [id]
    );

    res.json({ message: '가입을 승인했습니다.' });
  } catch (error) {
    console.error('Approve member error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Reject join request (host only)
app.post('/api/meetings/:id/reject/:userId', authMiddleware, async (req, res) => {
  try {
    const { id, userId } = req.params;

    // Check if user is host
    const hostCheck = await pool.query(
      'SELECT id FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND is_host = true',
      [id, req.user.id]
    );
    if (hostCheck.rows.length === 0) {
      return res.status(403).json({ message: '모임장만 가입을 거절할 수 있습니다.' });
    }

    // Update status to rejected
    const result = await pool.query(
      'UPDATE meeting_members SET status = $1 WHERE meeting_id = $2 AND user_id = $3 AND status = $4 RETURNING id',
      ['rejected', id, userId, 'pending']
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '가입 신청을 찾을 수 없습니다.' });
    }

    res.json({ message: '가입을 거절했습니다.' });
  } catch (error) {
    console.error('Reject member error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Kick member (host only)
app.delete('/api/meetings/:id/kick/:userId', authMiddleware, async (req, res) => {
  try {
    const { id, userId } = req.params;

    // Check if user is host
    const hostCheck = await pool.query(
      'SELECT id FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND is_host = true',
      [id, req.user.id]
    );
    if (hostCheck.rows.length === 0) {
      return res.status(403).json({ message: '모임장만 멤버를 강퇴할 수 있습니다.' });
    }

    // Cannot kick yourself (host)
    if (parseInt(userId) === req.user.id) {
      return res.status(400).json({ message: '자기 자신은 강퇴할 수 없습니다.' });
    }

    // Delete member
    const result = await pool.query(
      'DELETE FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND status = $3 RETURNING id',
      [id, userId, 'approved']
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '멤버를 찾을 수 없습니다.' });
    }

    // Update member count
    await pool.query(
      'UPDATE meetings SET member_count = member_count - 1 WHERE id = $1',
      [id]
    );

    res.json({ message: '멤버를 강퇴했습니다.' });
  } catch (error) {
    console.error('Kick member error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Leave meeting
app.post('/api/meetings/:id/leave', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND is_host = FALSE RETURNING id',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: '모임장은 탈퇴할 수 없습니다.' });
    }

    // Update member count
    await pool.query(
      'UPDATE meetings SET member_count = GREATEST(member_count - 1, 1) WHERE id = $1',
      [id]
    );

    res.json({ message: '모임을 탈퇴했습니다.' });
  } catch (error) {
    console.error('Leave meeting error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Toggle meeting like
app.post('/api/meetings/:id/like', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const existing = await pool.query(
      'SELECT id FROM meeting_likes WHERE meeting_id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (existing.rows.length > 0) {
      await pool.query(
        'DELETE FROM meeting_likes WHERE meeting_id = $1 AND user_id = $2',
        [id, req.user.id]
      );
      res.json({ liked: false });
    } else {
      await pool.query(
        'INSERT INTO meeting_likes (meeting_id, user_id) VALUES ($1, $2)',
        [id, req.user.id]
      );
      res.json({ liked: true });
    }
  } catch (error) {
    console.error('Toggle meeting like error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Get meeting members (approved only)
app.get('/api/meetings/:id/members', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      SELECT u.id, u.name, u.profile_image, mm.is_host, mm.joined_at, mm.status
      FROM meeting_members mm
      JOIN users u ON mm.user_id = u.id
      WHERE mm.meeting_id = $1 AND (mm.status = 'approved' OR mm.status IS NULL)
      ORDER BY mm.is_host DESC, mm.joined_at ASC
    `, [id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get meeting members error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Get meeting messages
app.get('/api/meetings/:id/messages', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { before, limit = 50 } = req.query;

    // Check if user is a member of the meeting
    const memberCheck = await pool.query(
      'SELECT id FROM meeting_members WHERE meeting_id = $1 AND user_id = $2',
      [id, req.user.id]
    );
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ message: '모임 멤버만 채팅을 볼 수 있습니다.' });
    }

    let query = `
      SELECT mm.id, mm.content, mm.message_type, mm.created_at,
             u.id as user_id, u.name as user_name, u.profile_image
      FROM meeting_messages mm
      JOIN users u ON mm.user_id = u.id
      WHERE mm.meeting_id = $1
    `;
    const params = [id];

    if (before) {
      query += ` AND mm.id < $2`;
      params.push(before);
    }

    query += ` ORDER BY mm.created_at DESC LIMIT $${params.length + 1}`;
    params.push(parseInt(limit));

    const result = await pool.query(query, params);

    // Return in chronological order (oldest first)
    res.json(result.rows.reverse());
  } catch (error) {
    console.error('Get meeting messages error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Send meeting message
app.post('/api/meetings/:id/messages', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { content, messageType = 'user' } = req.body;

    if (!content || content.trim() === '') {
      return res.status(400).json({ message: '메시지 내용이 필요합니다.' });
    }

    // Check if user is an approved member of the meeting
    const memberCheck = await pool.query(
      'SELECT id FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND (status = $3 OR status IS NULL)',
      [id, req.user.id, 'approved']
    );
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ message: '모임 멤버만 채팅을 보낼 수 있습니다.' });
    }

    const result = await pool.query(`
      INSERT INTO meeting_messages (meeting_id, user_id, content, message_type)
      VALUES ($1, $2, $3, $4)
      RETURNING id, content, message_type, created_at
    `, [id, req.user.id, content.trim(), messageType]);

    // Get user info for response
    const userResult = await pool.query(
      'SELECT id, name, profile_image FROM users WHERE id = $1',
      [req.user.id]
    );

    const message = {
      ...result.rows[0],
      user_id: req.user.id,
      user_name: userResult.rows[0].name,
      profile_image: userResult.rows[0].profile_image,
    };

    res.status(201).json(message);
  } catch (error) {
    console.error('Send meeting message error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Get unread message count for a meeting
app.get('/api/meetings/:id/unread-count', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // Get member record to find last_read_at
    const memberResult = await pool.query(
      'SELECT last_read_at FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND (status = $3 OR status IS NULL)',
      [id, req.user.id, 'approved']
    );

    if (memberResult.rows.length === 0) {
      return res.json({ count: 0 });
    }

    const lastReadAt = memberResult.rows[0].last_read_at;

    // Count messages after last_read_at (excluding own messages)
    let countResult;
    if (lastReadAt) {
      countResult = await pool.query(
        'SELECT COUNT(*) FROM meeting_messages WHERE meeting_id = $1 AND user_id != $2 AND created_at > $3',
        [id, req.user.id, lastReadAt]
      );
    } else {
      // If never read, count all messages from others
      countResult = await pool.query(
        'SELECT COUNT(*) FROM meeting_messages WHERE meeting_id = $1 AND user_id != $2',
        [id, req.user.id]
      );
    }

    res.json({ count: parseInt(countResult.rows[0].count) });
  } catch (error) {
    console.error('Get unread count error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Mark messages as read
app.post('/api/meetings/:id/mark-read', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query(
      'UPDATE meeting_members SET last_read_at = NOW() WHERE meeting_id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Mark read error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Meeting Schedule API ====================

// Get meeting schedules
app.get('/api/meetings/:id/schedules', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      SELECT ms.*, u.name as creator_name, u.profile_image as creator_image,
        (SELECT COUNT(*) FROM meeting_schedule_participants WHERE schedule_id = ms.id) as participant_count,
        EXISTS(SELECT 1 FROM meeting_schedule_participants WHERE schedule_id = ms.id AND user_id = $2) as is_joined
      FROM meeting_schedules ms
      JOIN users u ON ms.creator_id = u.id
      WHERE ms.meeting_id = $1
      ORDER BY ms.schedule_date ASC
    `, [id, req.user.id]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get meeting schedules error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Create meeting schedule
app.post('/api/meetings/:id/schedules', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, location, scheduleDate, maxParticipants } = req.body;

    if (!title || !scheduleDate) {
      return res.status(400).json({ message: '제목과 날짜는 필수입니다.' });
    }

    // Check if user is an approved member
    const memberCheck = await pool.query(
      'SELECT id FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND (status = $3 OR status IS NULL)',
      [id, req.user.id, 'approved']
    );
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ message: '모임 멤버만 일정을 만들 수 있습니다.' });
    }

    const result = await pool.query(`
      INSERT INTO meeting_schedules (meeting_id, creator_id, title, description, location, schedule_date, max_participants)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `, [id, req.user.id, title, description || '', location || '', scheduleDate, maxParticipants || 0]);

    // Creator auto-joins the schedule
    await pool.query(
      'INSERT INTO meeting_schedule_participants (schedule_id, user_id) VALUES ($1, $2)',
      [result.rows[0].id, req.user.id]
    );

    res.status(201).json({
      ...result.rows[0],
      participant_count: 1,
      is_joined: true
    });
  } catch (error) {
    console.error('Create meeting schedule error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Join meeting schedule
app.post('/api/meetings/:meetingId/schedules/:scheduleId/join', authMiddleware, async (req, res) => {
  try {
    const { meetingId, scheduleId } = req.params;

    // Check if user is a member of the meeting
    const memberCheck = await pool.query(
      'SELECT id FROM meeting_members WHERE meeting_id = $1 AND user_id = $2',
      [meetingId, req.user.id]
    );
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ message: '모임 멤버만 일정에 참여할 수 있습니다.' });
    }

    // Check max participants
    const schedule = await pool.query('SELECT max_participants FROM meeting_schedules WHERE id = $1', [scheduleId]);
    if (schedule.rows.length === 0) {
      return res.status(404).json({ message: '일정을 찾을 수 없습니다.' });
    }

    const maxParticipants = schedule.rows[0].max_participants;
    if (maxParticipants > 0) {
      const currentCount = await pool.query(
        'SELECT COUNT(*) FROM meeting_schedule_participants WHERE schedule_id = $1',
        [scheduleId]
      );
      if (parseInt(currentCount.rows[0].count) >= maxParticipants) {
        return res.status(400).json({ message: '참여 인원이 가득 찼습니다.' });
      }
    }

    await pool.query(
      'INSERT INTO meeting_schedule_participants (schedule_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [scheduleId, req.user.id]
    );

    res.json({ message: '일정에 참여했습니다.' });
  } catch (error) {
    console.error('Join meeting schedule error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Leave meeting schedule
app.post('/api/meetings/:meetingId/schedules/:scheduleId/leave', authMiddleware, async (req, res) => {
  try {
    const { scheduleId } = req.params;

    await pool.query(
      'DELETE FROM meeting_schedule_participants WHERE schedule_id = $1 AND user_id = $2',
      [scheduleId, req.user.id]
    );

    res.json({ message: '일정 참여를 취소했습니다.' });
  } catch (error) {
    console.error('Leave meeting schedule error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Delete meeting schedule (creator only)
app.delete('/api/meetings/:meetingId/schedules/:scheduleId', authMiddleware, async (req, res) => {
  try {
    const { scheduleId } = req.params;

    const result = await pool.query(
      'DELETE FROM meeting_schedules WHERE id = $1 AND creator_id = $2 RETURNING id',
      [scheduleId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ message: '일정을 삭제할 권한이 없습니다.' });
    }

    res.json({ message: '일정이 삭제되었습니다.' });
  } catch (error) {
    console.error('Delete meeting schedule error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Meeting Boards API ====================

// Get meeting boards
app.get('/api/meetings/:id/boards', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      SELECT mb.*, u.name as creator_name
      FROM meeting_boards mb
      LEFT JOIN users u ON mb.created_by = u.id
      WHERE mb.meeting_id = $1
      ORDER BY mb.created_at ASC
    `, [id]);

    // Always include default boards
    const defaultBoards = [
      { id: -1, name: '자유 게시판', is_default: true },
      { id: -2, name: '공지사항', is_default: true },
      { id: -3, name: '질문/답변', is_default: true },
    ];

    const customBoards = result.rows.map(b => ({ ...b, is_default: false }));

    res.json([...defaultBoards, ...customBoards]);
  } catch (error) {
    console.error('Get meeting boards error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Create meeting board
app.post('/api/meetings/:id/boards', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { name } = req.body;

    if (!name || name.trim() === '') {
      return res.status(400).json({ message: '게시판 이름을 입력해주세요.' });
    }

    // Check if user is an approved member
    const memberCheck = await pool.query(
      'SELECT id FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND (status = $3 OR status IS NULL)',
      [id, req.user.id, 'approved']
    );
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ message: '모임 멤버만 게시판을 만들 수 있습니다.' });
    }

    // Check for default board names
    const defaultNames = ['자유 게시판', '공지사항', '질문/답변', '전체'];
    if (defaultNames.includes(name.trim())) {
      return res.status(400).json({ message: '기본 게시판과 같은 이름은 사용할 수 없습니다.' });
    }

    const result = await pool.query(`
      INSERT INTO meeting_boards (meeting_id, name, created_by)
      VALUES ($1, $2, $3)
      RETURNING *
    `, [id, name.trim(), req.user.id]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json({ message: '이미 같은 이름의 게시판이 있습니다.' });
    }
    console.error('Create meeting board error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Delete meeting board
app.delete('/api/meetings/:meetingId/boards/:boardId', authMiddleware, async (req, res) => {
  try {
    const { meetingId, boardId } = req.params;

    // Check if user is host
    const hostCheck = await pool.query(
      'SELECT id FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND is_host = true',
      [meetingId, req.user.id]
    );

    // Or if user created the board
    const boardCheck = await pool.query(
      'SELECT id, name FROM meeting_boards WHERE id = $1 AND meeting_id = $2',
      [boardId, meetingId]
    );

    if (boardCheck.rows.length === 0) {
      return res.status(404).json({ message: '게시판을 찾을 수 없습니다.' });
    }

    const creatorCheck = await pool.query(
      'SELECT id FROM meeting_boards WHERE id = $1 AND created_by = $2',
      [boardId, req.user.id]
    );

    if (hostCheck.rows.length === 0 && creatorCheck.rows.length === 0) {
      return res.status(403).json({ message: '게시판을 삭제할 권한이 없습니다.' });
    }

    const boardName = boardCheck.rows[0].name;

    // Delete board
    await pool.query('DELETE FROM meeting_boards WHERE id = $1', [boardId]);

    // Move posts from deleted board to '자유 게시판'
    await pool.query(
      'UPDATE meeting_posts SET board_name = $1 WHERE meeting_id = $2 AND board_name = $3',
      ['자유 게시판', meetingId, boardName]
    );

    res.json({ message: '게시판이 삭제되었습니다.' });
  } catch (error) {
    console.error('Delete meeting board error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Meeting Posts API ====================

// Get meeting posts
app.get('/api/meetings/:id/posts', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { board } = req.query;

    let query = `
      SELECT mp.*, u.name as author_name, u.profile_image as author_image,
        (SELECT COUNT(*) FROM meeting_post_likes WHERE post_id = mp.id) as like_count,
        (SELECT COUNT(*) FROM meeting_post_comments WHERE post_id = mp.id) as comment_count,
        EXISTS(SELECT 1 FROM meeting_post_likes WHERE post_id = mp.id AND user_id = $2) as is_liked,
        EXISTS(SELECT 1 FROM meeting_members WHERE meeting_id = mp.meeting_id AND user_id = mp.author_id AND is_host = true) as is_host
      FROM meeting_posts mp
      JOIN users u ON mp.author_id = u.id
      WHERE mp.meeting_id = $1
    `;
    const params = [id, req.user.id];

    if (board && board !== '전체') {
      query += ' AND mp.board_name = $3';
      params.push(board);
    }

    query += ' ORDER BY mp.created_at DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Get meeting posts error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Create meeting post
app.post('/api/meetings/:id/posts', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { content, boardName, images } = req.body;

    if (!content) {
      return res.status(400).json({ message: '내용을 입력해주세요.' });
    }

    // Check if user is an approved member
    const memberCheck = await pool.query(
      'SELECT id, is_host FROM meeting_members WHERE meeting_id = $1 AND user_id = $2 AND (status = $3 OR status IS NULL)',
      [id, req.user.id, 'approved']
    );
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ message: '모임 멤버만 글을 작성할 수 있습니다.' });
    }

    const result = await pool.query(`
      INSERT INTO meeting_posts (meeting_id, author_id, board_name, content, images)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `, [id, req.user.id, boardName || '자유 게시판', content, images ? JSON.stringify(images) : null]);

    const user = await pool.query('SELECT name, profile_image FROM users WHERE id = $1', [req.user.id]);

    res.status(201).json({
      ...result.rows[0],
      author_name: user.rows[0].name,
      author_image: user.rows[0].profile_image,
      is_host: memberCheck.rows[0].is_host,
      like_count: 0,
      comment_count: 0,
      is_liked: false
    });
  } catch (error) {
    console.error('Create meeting post error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Toggle post like
app.post('/api/meetings/:meetingId/posts/:postId/like', authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;

    const existingLike = await pool.query(
      'SELECT id FROM meeting_post_likes WHERE post_id = $1 AND user_id = $2',
      [postId, req.user.id]
    );

    if (existingLike.rows.length > 0) {
      await pool.query(
        'DELETE FROM meeting_post_likes WHERE post_id = $1 AND user_id = $2',
        [postId, req.user.id]
      );
      res.json({ liked: false });
    } else {
      await pool.query(
        'INSERT INTO meeting_post_likes (post_id, user_id) VALUES ($1, $2)',
        [postId, req.user.id]
      );
      res.json({ liked: true });
    }
  } catch (error) {
    console.error('Toggle post like error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Get post comments
app.get('/api/meetings/:meetingId/posts/:postId/comments', authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;

    const result = await pool.query(`
      SELECT c.*, u.name as author_name, u.profile_image as author_image
      FROM meeting_post_comments c
      JOIN users u ON c.author_id = u.id
      WHERE c.post_id = $1
      ORDER BY c.created_at ASC
    `, [postId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get post comments error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Add comment to post
app.post('/api/meetings/:meetingId/posts/:postId/comments', authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ message: '댓글 내용을 입력해주세요.' });
    }

    const result = await pool.query(`
      INSERT INTO meeting_post_comments (post_id, author_id, content)
      VALUES ($1, $2, $3)
      RETURNING *
    `, [postId, req.user.id, content]);

    const user = await pool.query('SELECT name, profile_image FROM users WHERE id = $1', [req.user.id]);

    res.status(201).json({
      ...result.rows[0],
      author_name: user.rows[0].name,
      author_image: user.rows[0].profile_image
    });
  } catch (error) {
    console.error('Add post comment error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Delete post (author only)
app.delete('/api/meetings/:meetingId/posts/:postId', authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;

    const result = await pool.query(
      'DELETE FROM meeting_posts WHERE id = $1 AND author_id = $2 RETURNING id',
      [postId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ message: '게시글을 삭제할 권한이 없습니다.' });
    }

    res.json({ message: '게시글이 삭제되었습니다.' });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Prescription API ====================

// 처방전 OCR 파싱 프롬프트
const PRESCRIPTION_PARSE_PROMPT = `처방전 이미지에서 환자 정보와 약품 정보를 추출해 JSON으로 반환하세요.

반환 형식:
{
  "gender": "M" 또는 "F",
  "age": 나이 (숫자),
  "medications": [
    {
      "drug_name": "약품명",
      "strength": "용량 (예: 500mg, 10mg/5ml)",
      "single_dose": "1회 복용량 (예: 1정, 2캡슐, 5ml)",
      "frequency": 하루 복용 횟수 (숫자),
      "duration": 투약 일수 (숫자)
    }
  ]
}

규칙:
- 주민번호(YYMMDD-NXXXXXX) 감지 시:
  - 뒷자리 첫번째 숫자: 1,3 → "M"(남), 2,4 → "F"(여)
  - 나이 계산: 1,2로 시작하면 1900년대생, 3,4로 시작하면 2000년대생
  - 예: 850315-1XXXXXX → 남성, 만 나이 계산
- 성별: 남/남자/M → "M", 여/여자/F → "F"
- 약품명에서 용량(mg, mcg, ml 등)을 분리하여 strength에 기입
- 읽을 수 없는 필드는 null
- JSON만 반환, 다른 텍스트 없이`;

// 처방전 분석 프롬프트
const PRESCRIPTION_ANALYZE_PROMPT = `당신은 전문 약사입니다. 다음 처방전 정보를 분석해주세요.

## 환자 정보
- 성별: {gender}
- 나이: {age}세

## 처방 약품
{medications}

## 분석 요청

### 1. 처방 종합 분석 (필수)
- 이 처방의 전체적인 치료 목적/의도 추론
- 어떤 질환/증상을 타겟으로 한 처방인지
- 약품들 간의 조합 의도 설명

### 2. 개별 약품 검토
- 각 약품의 역할
- 용법·용량 적절성

### 3. 주의사항
- 약물 간 상호작용
- 환자 나이/성별 고려사항
- 복약지도 포인트

간결하고 실용적으로 답변해주세요.`;

// POST /api/prescription/parse - 처방전 OCR
app.post('/api/prescription/parse', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ parse_success: false, error: '이미지 파일이 필요합니다.' });
    }

    const imageBase64 = req.file.buffer.toString('base64');

    // 이미지 타입 감지 (매직 바이트 사용)
    const buffer = req.file.buffer;
    let mimeType = 'image/jpeg'; // 기본값

    if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
      mimeType = 'image/jpeg';
    } else if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
      mimeType = 'image/png';
    } else if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46) {
      mimeType = 'image/gif';
    } else if (buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46) {
      mimeType = 'image/webp';
    }

    console.log('Detected mimeType:', mimeType, 'Original:', req.file.mimetype);

    // Gemini 2.0 Flash로 OCR
    const result = await ai.models.generateContent({
      model: 'gemini-2.0-flash',
      contents: [{
        role: 'user',
        parts: [
          { text: PRESCRIPTION_PARSE_PROMPT },
          {
            inlineData: {
              mimeType: mimeType,
              data: imageBase64
            }
          }
        ]
      }],
      config: {
        temperature: 0.1,
      }
    });

    const responseText = result?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    console.log('Gemini OCR response:', responseText);

    // JSON 추출
    let parsed;
    try {
      // JSON 블록 추출 시도
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        parsed = JSON.parse(jsonMatch[0]);
      } else {
        throw new Error('No JSON found');
      }
    } catch (e) {
      console.error('JSON parse error:', e);
      return res.json({
        parse_success: false,
        gender: null,
        age: null,
        medications: []
      });
    }

    res.json({
      parse_success: true,
      gender: parsed.gender || null,
      age: parsed.age || null,
      medications: (parsed.medications || []).map(m => ({
        drug_name: m.drug_name || '',
        strength: m.strength || '',
        single_dose: m.single_dose || '1정',
        frequency: m.frequency || 1,
        duration: m.duration || 1
      }))
    });

  } catch (error) {
    console.error('Prescription parse error:', error);
    res.status(500).json({
      parse_success: false,
      error: '처방전 분석 중 오류가 발생했습니다.'
    });
  }
});

// POST /api/prescription/analyze - 처방전 분석
app.post('/api/prescription/analyze', authMiddleware, async (req, res) => {
  try {
    const { gender, age, medications } = req.body;

    if (!medications || medications.length === 0) {
      return res.status(400).json({ error: '약품 정보가 필요합니다.' });
    }

    // 약품 목록 포맷팅
    const medicationList = medications.map((m, i) =>
      `${i + 1}. ${m.drug_name} - ${m.single_dose} x ${m.frequency}회/일 x ${m.duration}일`
    ).join('\n');

    // 프롬프트 생성
    const prompt = PRESCRIPTION_ANALYZE_PROMPT
      .replace('{gender}', gender === 'M' ? '남성' : '여성')
      .replace('{age}', age || '미상')
      .replace('{medications}', medicationList);

    // Gemini로 분석 (RAG 없이 빠른 분석)
    const result = await ai.models.generateContent({
      model: 'gemini-2.0-flash',
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      config: {
        temperature: 0.3,
        systemInstruction: `당신은 전문 약사입니다. 처방전을 검토하고 약물 상호작용, 부작용, 복용법에 대해 정확하게 분석해주세요.`,
      },
    });

    const analysisText = result?.candidates?.[0]?.content?.parts?.[0]?.text || '';

    if (!analysisText) {
      return res.status(500).json({ error: '분석 결과를 생성하지 못했습니다.' });
    }

    res.json({ analysis: analysisText });

  } catch (error) {
    console.error('Prescription analyze error:', error);
    res.status(500).json({ error: '분석 중 오류가 발생했습니다.' });
  }
});

// ==================== UsedItem (중고거래) API ====================

// 중고거래 목록 조회
app.get('/api/used-items', authMiddleware, async (req, res) => {
  try {
    const { category, status, sort = 'latest', search, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    let query = `
      SELECT ui.*,
        u.name as author_name,
        u.profile_image as author_profile_image,
        u.user_type as author_user_type,
        u.reputation_score as author_reputation_score,
        EXISTS(SELECT 1 FROM used_item_likes WHERE item_id = ui.id AND user_id = $1) as is_liked,
        (SELECT COUNT(*) FROM used_item_likes WHERE item_id = ui.id) as like_count
      FROM used_items ui
      LEFT JOIN users u ON ui.author_id = u.id
      WHERE 1=1
    `;
    const params = [req.user.id];
    let paramIndex = 2;

    if (category && category !== 'all') {
      query += ` AND ui.category = $${paramIndex}`;
      params.push(category);
      paramIndex++;
    }

    if (status && status !== 'all') {
      query += ` AND ui.status = $${paramIndex}`;
      params.push(status);
      paramIndex++;
    }

    if (search && search.trim()) {
      query += ` AND (ui.title ILIKE $${paramIndex} OR ui.description ILIKE $${paramIndex})`;
      params.push(`%${search.trim()}%`);
      paramIndex++;
    }

    // 정렬
    let orderBy;
    switch (sort) {
      case 'priceLow':
        orderBy = 'ui.price ASC';
        break;
      case 'priceHigh':
        orderBy = 'ui.price DESC';
        break;
      case 'latest':
      default:
        orderBy = 'COALESCE(ui.bumped_at, ui.created_at) DESC';
        break;
    }
    query += ` ORDER BY ${orderBy} LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);

    const items = result.rows.map(item => ({
      id: item.id,
      title: item.title,
      description: item.description,
      price: item.price,
      isNegotiable: item.is_negotiable,
      images: item.images || [],
      category: item.category,
      condition: item.condition,
      status: item.status,
      location: item.location,
      authorId: item.author_id,
      authorName: item.author_name,
      authorProfileImage: item.author_profile_image,
      authorUserType: item.author_user_type,
      authorReputationScore: item.author_reputation_score,
      viewCount: item.view_count,
      chatCount: item.chat_count,
      likeCount: parseInt(item.like_count) || 0,
      isLiked: item.is_liked,
      createdAt: item.created_at,
      bumpedAt: item.bumped_at
    }));

    res.json(items);
  } catch (error) {
    console.error('Get used items error:', error);
    res.status(500).json({ message: '상품 목록을 불러오는데 실패했습니다.' });
  }
});

// 중고거래 상세 조회
app.get('/api/used-items/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // 조회수 증가
    await pool.query('UPDATE used_items SET view_count = view_count + 1 WHERE id = $1', [id]);

    const result = await pool.query(`
      SELECT ui.*,
        u.name as author_name,
        u.profile_image as author_profile_image,
        u.user_type as author_user_type,
        u.reputation_score as author_reputation_score,
        EXISTS(SELECT 1 FROM used_item_likes WHERE item_id = ui.id AND user_id = $1) as is_liked,
        (SELECT COUNT(*) FROM used_item_likes WHERE item_id = ui.id) as like_count
      FROM used_items ui
      LEFT JOIN users u ON ui.author_id = u.id
      WHERE ui.id = $2
    `, [req.user.id, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: '상품을 찾을 수 없습니다.' });
    }

    const item = result.rows[0];
    res.json({
      id: item.id,
      title: item.title,
      description: item.description,
      price: item.price,
      isNegotiable: item.is_negotiable,
      images: item.images || [],
      category: item.category,
      condition: item.condition,
      status: item.status,
      location: item.location,
      authorId: item.author_id,
      authorName: item.author_name,
      authorProfileImage: item.author_profile_image,
      authorUserType: item.author_user_type,
      authorReputationScore: item.author_reputation_score,
      viewCount: item.view_count,
      chatCount: item.chat_count,
      likeCount: parseInt(item.like_count) || 0,
      isLiked: item.is_liked,
      createdAt: item.created_at,
      bumpedAt: item.bumped_at
    });
  } catch (error) {
    console.error('Get used item error:', error);
    res.status(500).json({ message: '상품을 불러오는데 실패했습니다.' });
  }
});

// 중고거래 등록
app.post('/api/used-items', authMiddleware, async (req, res) => {
  try {
    const { title, description, price, category, condition, location, isNegotiable, images } = req.body;

    if (!title || !category || !condition) {
      return res.status(400).json({ message: '필수 항목을 입력해주세요.' });
    }

    const result = await pool.query(`
      INSERT INTO used_items (title, description, price, is_negotiable, images, category, condition, location, author_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `, [title, description || '', price || 0, isNegotiable || false, images || [], category, condition, location || '', req.user.id]);

    const item = result.rows[0];
    res.status(201).json({
      id: item.id,
      title: item.title,
      description: item.description,
      price: item.price,
      isNegotiable: item.is_negotiable,
      images: item.images || [],
      category: item.category,
      condition: item.condition,
      status: item.status,
      location: item.location,
      authorId: item.author_id,
      authorName: req.user.name,
      authorProfileImage: req.user.profile_image,
      authorUserType: req.user.user_type,
      authorReputationScore: req.user.reputation_score,
      viewCount: item.view_count,
      chatCount: item.chat_count,
      likeCount: 0,
      isLiked: false,
      createdAt: item.created_at,
      bumpedAt: item.bumped_at
    });
  } catch (error) {
    console.error('Create used item error:', error);
    res.status(500).json({ message: '상품 등록에 실패했습니다.' });
  }
});

// 중고거래 수정
app.put('/api/used-items/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, price, category, condition, location, isNegotiable, images } = req.body;

    // 권한 확인
    const checkResult = await pool.query('SELECT author_id FROM used_items WHERE id = $1', [id]);
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ message: '상품을 찾을 수 없습니다.' });
    }
    if (checkResult.rows[0].author_id !== req.user.id) {
      return res.status(403).json({ message: '수정 권한이 없습니다.' });
    }

    const result = await pool.query(`
      UPDATE used_items
      SET title = COALESCE($1, title),
          description = COALESCE($2, description),
          price = COALESCE($3, price),
          category = COALESCE($4, category),
          condition = COALESCE($5, condition),
          location = COALESCE($6, location),
          is_negotiable = COALESCE($7, is_negotiable),
          images = COALESCE($8, images)
      WHERE id = $9
      RETURNING *
    `, [title, description, price, category, condition, location, isNegotiable, images, id]);

    const item = result.rows[0];
    res.json({
      id: item.id,
      title: item.title,
      description: item.description,
      price: item.price,
      isNegotiable: item.is_negotiable,
      images: item.images || [],
      category: item.category,
      condition: item.condition,
      status: item.status,
      location: item.location,
      authorId: item.author_id,
      viewCount: item.view_count,
      chatCount: item.chat_count,
      createdAt: item.created_at,
      bumpedAt: item.bumped_at
    });
  } catch (error) {
    console.error('Update used item error:', error);
    res.status(500).json({ message: '상품 수정에 실패했습니다.' });
  }
});

// 중고거래 삭제
app.delete('/api/used-items/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // 권한 확인
    const checkResult = await pool.query('SELECT author_id FROM used_items WHERE id = $1', [id]);
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ message: '상품을 찾을 수 없습니다.' });
    }
    if (checkResult.rows[0].author_id !== req.user.id) {
      return res.status(403).json({ message: '삭제 권한이 없습니다.' });
    }

    await pool.query('DELETE FROM used_items WHERE id = $1', [id]);
    res.json({ message: '상품이 삭제되었습니다.' });
  } catch (error) {
    console.error('Delete used item error:', error);
    res.status(500).json({ message: '상품 삭제에 실패했습니다.' });
  }
});

// 중고거래 좋아요 토글
app.post('/api/used-items/:id/like', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    const existingLike = await pool.query(
      'SELECT id FROM used_item_likes WHERE item_id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    let liked;
    if (existingLike.rows.length > 0) {
      await pool.query('DELETE FROM used_item_likes WHERE item_id = $1 AND user_id = $2', [id, req.user.id]);
      liked = false;
    } else {
      await pool.query('INSERT INTO used_item_likes (item_id, user_id) VALUES ($1, $2)', [id, req.user.id]);
      liked = true;
    }

    const countResult = await pool.query('SELECT COUNT(*) FROM used_item_likes WHERE item_id = $1', [id]);
    const likeCount = parseInt(countResult.rows[0].count);

    res.json({ liked, likeCount });
  } catch (error) {
    console.error('Toggle used item like error:', error);
    res.status(500).json({ message: '좋아요 처리에 실패했습니다.' });
  }
});

// 중고거래 끌어올리기
app.post('/api/used-items/:id/bump', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;

    // 권한 확인
    const checkResult = await pool.query('SELECT author_id FROM used_items WHERE id = $1', [id]);
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ message: '상품을 찾을 수 없습니다.' });
    }
    if (checkResult.rows[0].author_id !== req.user.id) {
      return res.status(403).json({ message: '끌어올리기 권한이 없습니다.' });
    }

    await pool.query('UPDATE used_items SET bumped_at = CURRENT_TIMESTAMP WHERE id = $1', [id]);
    res.json({ message: '끌어올리기가 완료되었습니다.' });
  } catch (error) {
    console.error('Bump used item error:', error);
    res.status(500).json({ message: '끌어올리기에 실패했습니다.' });
  }
});

// 중고거래 상태 변경
app.post('/api/used-items/:id/status', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!['available', 'reserved', 'sold'].includes(status)) {
      return res.status(400).json({ message: '유효하지 않은 상태입니다.' });
    }

    // 권한 확인
    const checkResult = await pool.query('SELECT author_id FROM used_items WHERE id = $1', [id]);
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ message: '상품을 찾을 수 없습니다.' });
    }
    if (checkResult.rows[0].author_id !== req.user.id) {
      return res.status(403).json({ message: '상태 변경 권한이 없습니다.' });
    }

    await pool.query('UPDATE used_items SET status = $1 WHERE id = $2', [status, id]);
    res.json({ status });
  } catch (error) {
    console.error('Update used item status error:', error);
    res.status(500).json({ message: '상태 변경에 실패했습니다.' });
  }
});

// 내 중고거래 목록
app.get('/api/used-items/my', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT ui.*,
        (SELECT COUNT(*) FROM used_item_likes WHERE item_id = ui.id) as like_count
      FROM used_items ui
      WHERE ui.author_id = $1
      ORDER BY ui.created_at DESC
    `, [req.user.id]);

    const items = result.rows.map(item => ({
      id: item.id,
      title: item.title,
      description: item.description,
      price: item.price,
      isNegotiable: item.is_negotiable,
      images: item.images || [],
      category: item.category,
      condition: item.condition,
      status: item.status,
      location: item.location,
      authorId: item.author_id,
      authorName: req.user.name,
      viewCount: item.view_count,
      chatCount: item.chat_count,
      likeCount: parseInt(item.like_count) || 0,
      isLiked: false,
      createdAt: item.created_at
    }));

    res.json(items);
  } catch (error) {
    console.error('Get my used items error:', error);
    res.status(500).json({ message: '내 상품 목록을 불러오는데 실패했습니다.' });
  }
});

// 관심 상품 목록
app.get('/api/used-items/liked', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT ui.*,
        u.name as author_name,
        u.profile_image as author_profile_image,
        (SELECT COUNT(*) FROM used_item_likes WHERE item_id = ui.id) as like_count
      FROM used_items ui
      INNER JOIN used_item_likes uil ON ui.id = uil.item_id
      LEFT JOIN users u ON ui.author_id = u.id
      WHERE uil.user_id = $1
      ORDER BY uil.created_at DESC
    `, [req.user.id]);

    const items = result.rows.map(item => ({
      id: item.id,
      title: item.title,
      description: item.description,
      price: item.price,
      isNegotiable: item.is_negotiable,
      images: item.images || [],
      category: item.category,
      condition: item.condition,
      status: item.status,
      location: item.location,
      authorId: item.author_id,
      authorName: item.author_name,
      authorProfileImage: item.author_profile_image,
      viewCount: item.view_count,
      chatCount: item.chat_count,
      likeCount: parseInt(item.like_count) || 0,
      isLiked: true,
      createdAt: item.created_at
    }));

    res.json(items);
  } catch (error) {
    console.error('Get liked used items error:', error);
    res.status(500).json({ message: '관심 상품 목록을 불러오는데 실패했습니다.' });
  }
});

// ==================== Direct Chat (1:1 채팅) API ====================

// Create or get chat for used item
app.post('/api/used-items/:id/chat', authMiddleware, async (req, res) => {
  try {
    const itemId = parseInt(req.params.id);
    const buyerId = req.user.id;

    // Get item info to find seller
    const itemResult = await pool.query('SELECT author_id FROM used_items WHERE id = $1', [itemId]);
    if (itemResult.rows.length === 0) {
      return res.status(404).json({ message: '상품을 찾을 수 없습니다.' });
    }

    const sellerId = itemResult.rows[0].author_id;

    // Can't chat with yourself
    if (buyerId === sellerId) {
      return res.status(400).json({ message: '자신의 상품에는 채팅할 수 없습니다.' });
    }

    // Check if chat already exists
    let chatResult = await pool.query(
      'SELECT * FROM direct_chats WHERE used_item_id = $1 AND buyer_id = $2',
      [itemId, buyerId]
    );

    if (chatResult.rows.length === 0) {
      // Create new chat
      chatResult = await pool.query(
        'INSERT INTO direct_chats (used_item_id, buyer_id, seller_id) VALUES ($1, $2, $3) RETURNING *',
        [itemId, buyerId, sellerId]
      );

      // Increment chat count on item
      await pool.query('UPDATE used_items SET chat_count = chat_count + 1 WHERE id = $1', [itemId]);
    }

    const chat = chatResult.rows[0];

    // Get item and user info
    const itemInfo = await pool.query(`
      SELECT ui.title, ui.price, ui.images, ui.status,
        seller.name as seller_name, seller.profile_image as seller_image,
        buyer.name as buyer_name, buyer.profile_image as buyer_image
      FROM used_items ui
      LEFT JOIN users seller ON ui.author_id = seller.id
      LEFT JOIN users buyer ON buyer.id = $2
      WHERE ui.id = $1
    `, [itemId, buyerId]);

    const info = itemInfo.rows[0];

    res.json({
      chatId: chat.id,
      usedItemId: chat.used_item_id,
      buyerId: chat.buyer_id,
      sellerId: chat.seller_id,
      createdAt: chat.created_at,
      itemTitle: info.title,
      itemPrice: info.price,
      itemImage: info.images?.[0] || null,
      itemStatus: info.status,
      sellerName: info.seller_name,
      sellerImage: info.seller_image,
      buyerName: info.buyer_name,
      buyerImage: info.buyer_image
    });
  } catch (error) {
    console.error('Create/get chat error:', error);
    res.status(500).json({ message: '채팅방을 생성하는데 실패했습니다.' });
  }
});

// Get chat messages
app.get('/api/chats/:chatId/messages', authMiddleware, async (req, res) => {
  try {
    const chatId = parseInt(req.params.chatId);
    const userId = req.user.id;

    // Verify user is part of this chat
    const chatResult = await pool.query(
      'SELECT * FROM direct_chats WHERE id = $1 AND (buyer_id = $2 OR seller_id = $2)',
      [chatId, userId]
    );

    if (chatResult.rows.length === 0) {
      return res.status(403).json({ message: '이 채팅에 접근할 권한이 없습니다.' });
    }

    const result = await pool.query(`
      SELECT dm.*, u.name as sender_name, u.profile_image as sender_image
      FROM direct_messages dm
      LEFT JOIN users u ON dm.sender_id = u.id
      WHERE dm.chat_id = $1
      ORDER BY dm.created_at ASC
    `, [chatId]);

    const messages = result.rows.map(m => ({
      id: m.id,
      chatId: m.chat_id,
      senderId: m.sender_id,
      senderName: m.sender_name,
      senderImage: m.sender_image,
      content: m.content,
      createdAt: m.created_at,
      isMe: m.sender_id === userId
    }));

    res.json(messages);
  } catch (error) {
    console.error('Get chat messages error:', error);
    res.status(500).json({ message: '메시지를 불러오는데 실패했습니다.' });
  }
});

// Send chat message
app.post('/api/chats/:chatId/messages', authMiddleware, async (req, res) => {
  try {
    const chatId = parseInt(req.params.chatId);
    const userId = req.user.id;
    const { content } = req.body;

    if (!content || content.trim() === '') {
      return res.status(400).json({ message: '메시지 내용을 입력해주세요.' });
    }

    // Verify user is part of this chat
    const chatResult = await pool.query(
      'SELECT * FROM direct_chats WHERE id = $1 AND (buyer_id = $2 OR seller_id = $2)',
      [chatId, userId]
    );

    if (chatResult.rows.length === 0) {
      return res.status(403).json({ message: '이 채팅에 접근할 권한이 없습니다.' });
    }

    const result = await pool.query(
      'INSERT INTO direct_messages (chat_id, sender_id, content) VALUES ($1, $2, $3) RETURNING *',
      [chatId, userId, content.trim()]
    );

    const message = result.rows[0];

    res.json({
      id: message.id,
      chatId: message.chat_id,
      senderId: message.sender_id,
      senderName: req.user.name,
      senderImage: req.user.profile_image,
      content: message.content,
      createdAt: message.created_at,
      isMe: true
    });
  } catch (error) {
    console.error('Send chat message error:', error);
    res.status(500).json({ message: '메시지 전송에 실패했습니다.' });
  }
});

// Get my chats
app.get('/api/chats/my', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await pool.query(`
      SELECT dc.*,
        ui.title as item_title, ui.price as item_price, ui.images as item_images, ui.status as item_status,
        seller.name as seller_name, seller.profile_image as seller_image,
        buyer.name as buyer_name, buyer.profile_image as buyer_image,
        (SELECT content FROM direct_messages WHERE chat_id = dc.id ORDER BY created_at DESC LIMIT 1) as last_message,
        (SELECT created_at FROM direct_messages WHERE chat_id = dc.id ORDER BY created_at DESC LIMIT 1) as last_message_at
      FROM direct_chats dc
      LEFT JOIN used_items ui ON dc.used_item_id = ui.id
      LEFT JOIN users seller ON dc.seller_id = seller.id
      LEFT JOIN users buyer ON dc.buyer_id = buyer.id
      WHERE dc.buyer_id = $1 OR dc.seller_id = $1
      ORDER BY COALESCE(
        (SELECT created_at FROM direct_messages WHERE chat_id = dc.id ORDER BY created_at DESC LIMIT 1),
        dc.created_at
      ) DESC
    `, [userId]);

    const chats = result.rows.map(c => ({
      chatId: c.id,
      usedItemId: c.used_item_id,
      buyerId: c.buyer_id,
      sellerId: c.seller_id,
      createdAt: c.created_at,
      itemTitle: c.item_title,
      itemPrice: c.item_price,
      itemImage: c.item_images?.[0] || null,
      itemStatus: c.item_status,
      sellerName: c.seller_name,
      sellerImage: c.seller_image,
      buyerName: c.buyer_name,
      buyerImage: c.buyer_image,
      lastMessage: c.last_message,
      lastMessageAt: c.last_message_at,
      isMyItem: c.seller_id === userId
    }));

    res.json(chats);
  } catch (error) {
    console.error('Get my chats error:', error);
    res.status(500).json({ message: '채팅 목록을 불러오는데 실패했습니다.' });
  }
});

// Health check
app.get('/', (req, res) => {
  res.json({ message: 'Yaktong API Server', status: 'running' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Start server (skip if running tests)
if (process.env.NODE_ENV !== 'test') {
  initDB().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server running on port ${PORT}`);
    });
  });
}

// Export for testing
module.exports = { app, pool, initDB };
