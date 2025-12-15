const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { GoogleGenAI } = require('@google/genai');

const app = express();

// Gemini AI Setup
const ai = new GoogleGenAI({ apiKey: 'AIzaSyAiuUG-stKkhynH-RRf06SbHvlh7bkr2eA' });
const ABS_STORE = 'fileSearchStores/mfdsdrugstore1765718067-0689ta6mprlg';
const REL_STORE = 'fileSearchStores/ymydstore1765791970-4k6wvcc5h5id';
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

const aiChats = {};
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'yaktong-secret-key-2024';

// Middleware
app.use(cors());
app.use(express.json());

// In-memory database (for demo purposes)
const users = [];
const posts = [];
const comments = [];
const notices = [
  {
    id: 1,
    title: '약통 서비스 오픈!',
    content: '약사 커뮤니티 약통이 오픈했습니다. 많은 이용 부탁드립니다.',
    createdAt: new Date().toISOString()
  }
];

let userIdCounter = 1;
let postIdCounter = 1;
let commentIdCounter = 1;

// Auth middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: '인증이 필요합니다.' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = users.find(u => u.id === decoded.userId);
    if (!req.user) {
      return res.status(401).json({ message: '유효하지 않은 토큰입니다.' });
    }
    next();
  } catch (error) {
    return res.status(401).json({ message: '토큰이 만료되었습니다.' });
  }
};

// ==================== Auth API ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ message: '모든 필드를 입력해주세요.' });
    }

    if (users.find(u => u.email === email)) {
      return res.status(400).json({ message: '이미 등록된 이메일입니다.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      id: userIdCounter++,
      email,
      password: hashedPassword,
      name,
      phone: null,
      isAdmin: users.length === 0, // First user is admin
      createdAt: new Date().toISOString()
    };
    users.push(user);

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        isAdmin: user.isAdmin,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다.' });
    }

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
        isAdmin: user.isAdmin,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Change password
app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const isValidPassword = await bcrypt.compare(currentPassword, req.user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: '현재 비밀번호가 올바르지 않습니다.' });
    }

    req.user.password = await bcrypt.hash(newPassword, 10);
    res.json({ message: '비밀번호가 변경되었습니다.' });
  } catch (error) {
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
});

// Update nickname
app.post('/api/auth/nickname', authMiddleware, (req, res) => {
  const { nickname } = req.body;
  req.user.name = nickname;
  res.json({ message: '닉네임이 변경되었습니다.' });
});

// Update phone
app.post('/api/auth/phone', authMiddleware, (req, res) => {
  const { phone } = req.body;
  req.user.phone = phone;
  res.json({ message: '전화번호가 변경되었습니다.' });
});

// Check nickname availability
app.post('/api/auth/check-nickname', authMiddleware, (req, res) => {
  const { nickname } = req.body;
  const exists = users.some(u => u.name === nickname && u.id !== req.user.id);
  res.json({ available: !exists });
});

// Delete account
app.post('/api/auth/delete-account', authMiddleware, async (req, res) => {
  const { password } = req.body;

  const isValidPassword = await bcrypt.compare(password, req.user.password);
  if (!isValidPassword) {
    return res.status(401).json({ message: '비밀번호가 올바르지 않습니다.' });
  }

  const index = users.findIndex(u => u.id === req.user.id);
  if (index > -1) users.splice(index, 1);

  res.json({ message: '계정이 삭제되었습니다.' });
});

// ==================== Post API ====================

// Get posts
app.get('/api/posts', authMiddleware, (req, res) => {
  const { category, page = 1, limit = 20 } = req.query;

  let filteredPosts = [...posts];
  if (category && category !== 'all') {
    filteredPosts = filteredPosts.filter(p => p.category === category);
  }

  filteredPosts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  const start = (page - 1) * limit;
  const paginatedPosts = filteredPosts.slice(start, start + parseInt(limit));

  res.json({ posts: paginatedPosts });
});

// Get single post
app.get('/api/posts/:id', authMiddleware, (req, res) => {
  const post = posts.find(p => p.id === parseInt(req.params.id));
  if (!post) {
    return res.status(404).json({ message: '게시글을 찾을 수 없습니다.' });
  }
  post.viewCount = (post.viewCount || 0) + 1;
  res.json(post);
});

// Create post
app.post('/api/posts', authMiddleware, (req, res) => {
  const { title, content, category, isAnonymous } = req.body;

  const post = {
    id: postIdCounter++,
    title,
    content,
    category,
    isAnonymous,
    authorId: req.user.id,
    authorName: isAnonymous ? '익명' : req.user.name,
    likeCount: 0,
    commentCount: 0,
    viewCount: 0,
    likedBy: [],
    createdAt: new Date().toISOString()
  };
  posts.push(post);

  res.json(post);
});

// Delete post
app.delete('/api/posts/:id', authMiddleware, (req, res) => {
  const index = posts.findIndex(p => p.id === parseInt(req.params.id) && p.authorId === req.user.id);
  if (index === -1) {
    return res.status(404).json({ message: '게시글을 찾을 수 없습니다.' });
  }
  posts.splice(index, 1);
  res.json({ message: '게시글이 삭제되었습니다.' });
});

// Toggle post like
app.post('/api/posts/:id/like', authMiddleware, (req, res) => {
  const post = posts.find(p => p.id === parseInt(req.params.id));
  if (!post) {
    return res.status(404).json({ message: '게시글을 찾을 수 없습니다.' });
  }

  const likeIndex = post.likedBy.indexOf(req.user.id);
  if (likeIndex > -1) {
    post.likedBy.splice(likeIndex, 1);
    post.likeCount--;
    res.json({ liked: false, likeCount: post.likeCount });
  } else {
    post.likedBy.push(req.user.id);
    post.likeCount++;
    res.json({ liked: true, likeCount: post.likeCount });
  }
});

// Search posts
app.get('/api/posts/search', authMiddleware, (req, res) => {
  const { q } = req.query;
  const results = posts.filter(p =>
    p.title.includes(q) || p.content.includes(q)
  );
  res.json(results);
});

// My posts
app.get('/api/posts/my', authMiddleware, (req, res) => {
  const myPosts = posts.filter(p => p.authorId === req.user.id);
  res.json(myPosts);
});

// My comments
app.get('/api/posts/my/comments', authMiddleware, (req, res) => {
  const myComments = comments.filter(c => c.authorId === req.user.id);
  res.json(myComments);
});

// My likes
app.get('/api/posts/my/likes', authMiddleware, (req, res) => {
  const likedPosts = posts.filter(p => p.likedBy.includes(req.user.id));
  res.json(likedPosts);
});

// ==================== Comment API ====================

// Get comments for a post
app.get('/api/posts/:postId/comments', authMiddleware, (req, res) => {
  const postComments = comments.filter(c => c.postId === parseInt(req.params.postId));
  res.json(postComments);
});

// Create comment
app.post('/api/posts/:postId/comments', authMiddleware, (req, res) => {
  const { content } = req.body;
  const postId = parseInt(req.params.postId);

  const post = posts.find(p => p.id === postId);
  if (!post) {
    return res.status(404).json({ message: '게시글을 찾을 수 없습니다.' });
  }

  const comment = {
    id: commentIdCounter++,
    postId,
    content,
    authorId: req.user.id,
    authorName: req.user.name,
    likeCount: 0,
    likedBy: [],
    createdAt: new Date().toISOString()
  };
  comments.push(comment);
  post.commentCount++;

  res.json(comment);
});

// Delete comment
app.delete('/api/comments/:id', authMiddleware, (req, res) => {
  const index = comments.findIndex(c => c.id === parseInt(req.params.id) && c.authorId === req.user.id);
  if (index === -1) {
    return res.status(404).json({ message: '댓글을 찾을 수 없습니다.' });
  }

  const comment = comments[index];
  const post = posts.find(p => p.id === comment.postId);
  if (post) post.commentCount--;

  comments.splice(index, 1);
  res.json({ message: '댓글이 삭제되었습니다.' });
});

// Toggle comment like
app.post('/api/comments/:id/like', authMiddleware, (req, res) => {
  const comment = comments.find(c => c.id === parseInt(req.params.id));
  if (!comment) {
    return res.status(404).json({ message: '댓글을 찾을 수 없습니다.' });
  }

  const likeIndex = comment.likedBy.indexOf(req.user.id);
  if (likeIndex > -1) {
    comment.likedBy.splice(likeIndex, 1);
    comment.likeCount--;
    res.json({ liked: false });
  } else {
    comment.likedBy.push(req.user.id);
    comment.likeCount++;
    res.json({ liked: true });
  }
});

// ==================== AI API ====================

app.post('/api/ai/chat', authMiddleware, async (req, res) => {
  try {
    const { message, sessionId } = req.body;
    const oderId = sessionId || `session_${req.user.id}_${Date.now()}`;

    // Get or create chat session
    if (!aiChats[oderId]) {
      aiChats[oderId] = ai.chats.create({
        model: 'gemini-2.5-flash',
        config: {
          temperature: 0.3,
          systemInstruction: AI_SYSTEM_PROMPT,
          tools: [{
            fileSearch: {
              fileSearchStoreNames: [ABS_STORE, REL_STORE]
            }
          }]
        }
      });
    }

    const chat = await aiChats[oderId];
    const result = await chat.sendMessage({ message });
    const response = result.text || '';

    res.json({
      response: response.trim(),
      sessionId: oderId
    });
  } catch (error) {
    console.error('AI Chat Error:', error);
    res.status(500).json({
      response: '죄송합니다. AI 서비스에 일시적인 문제가 발생했습니다. 잠시 후 다시 시도해주세요.',
      error: error.message
    });
  }
});

// ==================== Notice API ====================

app.get('/api/notices', authMiddleware, (req, res) => {
  res.json(notices);
});

app.get('/api/notices/:id', authMiddleware, (req, res) => {
  const notice = notices.find(n => n.id === parseInt(req.params.id));
  if (!notice) {
    return res.status(404).json({ message: '공지사항을 찾을 수 없습니다.' });
  }
  res.json(notice);
});

// ==================== Admin API ====================

app.get('/api/admin/users', authMiddleware, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: '권한이 없습니다.' });
  }
  res.json(users.map(u => ({
    id: u.id,
    email: u.email,
    name: u.name,
    phone: u.phone,
    isAdmin: u.isAdmin,
    createdAt: u.createdAt
  })));
});

// Health check
app.get('/', (req, res) => {
  res.json({ message: 'Yaktong API Server', status: 'running' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
