const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
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

app.post('/api/ai/chat', authMiddleware, (req, res) => {
  const { message } = req.body;
  // Simple mock response
  res.json({
    response: `안녕하세요! "${message}"에 대한 답변입니다. 약사로서 도움이 필요하시면 말씀해주세요.`,
    sessionId: 'mock-session-id'
  });
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
