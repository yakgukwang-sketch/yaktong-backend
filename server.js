require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { GoogleGenAI } = require('@google/genai');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'yaktong-secret-key-2024';

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

// 세션별 대화 히스토리 저장
const aiSessions = {}; // { [sessionId]: Content[] }

// Middleware
app.use(cors());
app.use(express.json());

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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        category VARCHAR(50) DEFAULT 'daily',
        is_anonymous BOOLEAN DEFAULT FALSE,
        author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        author_name VARCHAR(100),
        like_count INTEGER DEFAULT 0,
        comment_count INTEGER DEFAULT 0,
        view_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

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
      'INSERT INTO users (email, password, name, is_admin) VALUES ($1, $2, $3, $4) RETURNING *',
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
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Login error:', error);
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

// ==================== Post API ====================

app.get('/api/posts', authMiddleware, async (req, res) => {
  try {
    const { category, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    let query = 'SELECT * FROM posts';
    let params = [];

    if (category && category !== 'all') {
      query += ' WHERE category = $1';
      params.push(category);
    }

    query += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
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
      "SELECT * FROM posts WHERE title ILIKE $1 OR content ILIKE $1 ORDER BY created_at DESC",
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
      'SELECT * FROM posts WHERE author_id = $1 ORDER BY created_at DESC',
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
      `SELECT p.* FROM posts p
       INNER JOIN post_likes pl ON p.id = pl.post_id
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

    await pool.query('UPDATE posts SET view_count = view_count + 1 WHERE id = $1', [postId]);

    const result = await pool.query('SELECT * FROM posts WHERE id = $1', [postId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: '게시글을 찾을 수 없습니다.' });
    }

    const likeResult = await pool.query(
      'SELECT id FROM post_likes WHERE post_id = $1 AND user_id = $2',
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
      likeCount: p.like_count,
      commentCount: p.comment_count,
      viewCount: p.view_count,
      createdAt: p.created_at,
      isLiked: likeResult.rows.length > 0
    });
  } catch (error) {
    console.error('Get post error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/posts', authMiddleware, async (req, res) => {
  try {
    const { title, content, category, isAnonymous } = req.body;
    const authorName = isAnonymous ? '익명' : req.user.name;

    const result = await pool.query(
      'INSERT INTO posts (title, content, category, is_anonymous, author_id, author_name) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [title, content, category || 'daily', isAnonymous || false, req.user.id, authorName]
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

    const existingLike = await pool.query(
      'SELECT id FROM post_likes WHERE post_id = $1 AND user_id = $2',
      [postId, req.user.id]
    );

    if (existingLike.rows.length > 0) {
      await pool.query('DELETE FROM post_likes WHERE post_id = $1 AND user_id = $2', [postId, req.user.id]);
      await pool.query('UPDATE posts SET like_count = like_count - 1 WHERE id = $1', [postId]);
      const result = await pool.query('SELECT like_count FROM posts WHERE id = $1', [postId]);
      res.json({ liked: false, likeCount: result.rows[0].like_count });
    } else {
      await pool.query('INSERT INTO post_likes (post_id, user_id) VALUES ($1, $2)', [postId, req.user.id]);
      await pool.query('UPDATE posts SET like_count = like_count + 1 WHERE id = $1', [postId]);
      const result = await pool.query('SELECT like_count FROM posts WHERE id = $1', [postId]);
      res.json({ liked: true, likeCount: result.rows[0].like_count });
    }
  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Comment API ====================

app.get('/api/posts/:postId/comments', authMiddleware, async (req, res) => {
  try {
    const postId = parseInt(req.params.postId);
    const result = await pool.query(
      'SELECT * FROM comments WHERE post_id = $1 ORDER BY created_at ASC',
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

    const result = await pool.query(
      'INSERT INTO comments (post_id, parent_id, content, author_id, author_name) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [postId, parentId || null, content, req.user.id, req.user.name]
    );

    await pool.query('UPDATE posts SET comment_count = comment_count + 1 WHERE id = $1', [postId]);

    const c = result.rows[0];
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

    const existingLike = await pool.query(
      'SELECT id FROM comment_likes WHERE comment_id = $1 AND user_id = $2',
      [commentId, req.user.id]
    );

    if (existingLike.rows.length > 0) {
      await pool.query('DELETE FROM comment_likes WHERE comment_id = $1 AND user_id = $2', [commentId, req.user.id]);
      await pool.query('UPDATE comments SET like_count = like_count - 1 WHERE id = $1', [commentId]);
      res.json({ liked: false });
    } else {
      await pool.query('INSERT INTO comment_likes (comment_id, user_id) VALUES ($1, $2)', [commentId, req.user.id]);
      await pool.query('UPDATE comments SET like_count = like_count + 1 WHERE id = $1', [commentId]);
      res.json({ liked: true });
    }
  } catch (error) {
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

    // 세션 초기화
    if (!aiSessions[sessionId]) {
      aiSessions[sessionId] = [];
    }

    // user turn 추가
    aiSessions[sessionId].push({
      role: "user",
      parts: [{ text: userMessage }]
    });

    // generateContent로 호출 (file_search 확실히 작동)
    const result = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: aiSessions[sessionId],
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

    // 디버그 로그 (확인 후 삭제)
    console.log("=== AI Debug ===");
    console.log("userMessage:", userMessage);
    console.log("Has groundingMetadata?:", !!result?.candidates?.[0]?.groundingMetadata);
    console.log("Has citationMetadata?:", !!result?.candidates?.[0]?.citationMetadata);

    const candidate = result?.candidates?.[0];

    // model turn을 history에 추가
    if (candidate?.content) {
      aiSessions[sessionId].push(candidate.content);
    }

    // 근거 확인 (citations 있는지 체크)
    const hasCitations =
      !!candidate?.groundingMetadata ||
      !!candidate?.citationMetadata ||
      JSON.stringify(result).toLowerCase().includes("citation");

    const responseText = result.text || candidate?.content?.parts?.[0]?.text || '';

    res.json({
      response: responseText.trim(),
      sessionId,
      hasCitations  // 프론트에서 근거 유무 표시용
    });

  } catch (error) {
    console.error('AI Chat Error:', error);
    res.status(500).json({
      response: '죄송합니다. AI 서비스에 일시적인 문제가 발생했습니다.',
      error: error.message
    });
  }
});

// ==================== Notice API ====================

app.get('/api/notices', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notices ORDER BY created_at DESC');
    res.json(result.rows);
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
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// ==================== Admin API ====================

app.get('/api/admin/users', authMiddleware, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: '권한이 없습니다.' });
    }

    const result = await pool.query('SELECT id, email, name, phone, is_admin, created_at FROM users');
    const users = result.rows.map(u => ({
      id: u.id,
      email: u.email,
      name: u.name,
      phone: u.phone,
      isAdmin: u.is_admin,
      createdAt: u.created_at
    }));

    res.json(users);
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Health check
app.get('/', (req, res) => {
  res.json({ message: 'Yaktong API Server', status: 'running' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Start server
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
  });
});
