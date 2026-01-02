const request = require('supertest');
const { app } = require('../../server');
const { createAuthenticatedUser } = require('../helpers/authHelper');
const { postFixtures } = require('../helpers/fixtures');

describe('Posts CRUD', () => {
  let authToken;
  let userId;

  beforeEach(async () => {
    const { user, token } = await createAuthenticatedUser();
    authToken = token;
    userId = user.id;
  });

  describe('GET /api/posts', () => {
    test('should return empty posts list initially', async () => {
      const res = await request(app)
        .get('/api/posts')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBe(0);
    });

    test('should return posts after creation', async () => {
      // Create a post first
      await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(postFixtures.validPost);

      const res = await request(app)
        .get('/api/posts')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.length).toBe(1);
      expect(res.body[0].title).toBe(postFixtures.validPost.title);
    });

    test('should filter posts by category', async () => {
      // Create posts with different categories
      await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(postFixtures.validPost); // category: 'question'

      await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(postFixtures.discussionPost); // category: 'discussion'

      const res = await request(app)
        .get('/api/posts?category=question')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.length).toBe(1);
      expect(res.body[0].category).toBe('question');
    });

    test('should require authentication', async () => {
      const res = await request(app)
        .get('/api/posts');

      expect(res.status).toBe(401);
    });
  });

  describe('POST /api/posts', () => {
    test('should create a new post', async () => {
      const res = await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(postFixtures.validPost);

      expect(res.status).toBe(201);
      expect(res.body.title).toBe(postFixtures.validPost.title);
      expect(res.body.content).toBe(postFixtures.validPost.content);
      expect(res.body.author_id).toBe(userId);
    });

    test('should create anonymous post', async () => {
      const res = await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(postFixtures.anonymousPost);

      expect(res.status).toBe(201);
      expect(res.body.is_anonymous).toBe(true);
      expect(res.body.author_name).toBe('익명');
    });

    test('should reject post without title', async () => {
      const res = await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          content: 'No title post',
          category: 'question'
        });

      expect(res.status).toBe(400);
    });

    test('should reject post without content', async () => {
      const res = await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: 'No content post',
          category: 'question'
        });

      expect(res.status).toBe(400);
    });

    test('should reject without authentication', async () => {
      const res = await request(app)
        .post('/api/posts')
        .send(postFixtures.validPost);

      expect(res.status).toBe(401);
    });
  });

  describe('GET /api/posts/:id', () => {
    test('should return post details', async () => {
      // Create a post first
      const createRes = await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(postFixtures.validPost);

      const postId = createRes.body.id;

      const res = await request(app)
        .get(`/api/posts/${postId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.id).toBe(postId);
      expect(res.body.title).toBe(postFixtures.validPost.title);
    });

    test('should increment view count', async () => {
      const createRes = await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(postFixtures.validPost);

      const postId = createRes.body.id;

      // First view
      await request(app)
        .get(`/api/posts/${postId}`)
        .set('Authorization', `Bearer ${authToken}`);

      // Second view
      const res = await request(app)
        .get(`/api/posts/${postId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.body.view_count).toBeGreaterThanOrEqual(1);
    });

    test('should return 404 for non-existent post', async () => {
      const res = await request(app)
        .get('/api/posts/99999')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(404);
    });
  });

  describe('DELETE /api/posts/:id', () => {
    test('should delete own post', async () => {
      const createRes = await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(postFixtures.validPost);

      const postId = createRes.body.id;

      const res = await request(app)
        .delete(`/api/posts/${postId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);

      // Verify deletion
      const getRes = await request(app)
        .get(`/api/posts/${postId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(getRes.status).toBe(404);
    });

    test('should not delete other user post', async () => {
      const createRes = await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${authToken}`)
        .send(postFixtures.validPost);

      const postId = createRes.body.id;

      // Create another user
      const { token: otherToken } = await createAuthenticatedUser({
        email: 'other@yaktong.com'
      });

      const res = await request(app)
        .delete(`/api/posts/${postId}`)
        .set('Authorization', `Bearer ${otherToken}`);

      // Should succeed but not actually delete (no rows affected)
      expect(res.status).toBe(200);

      // Post should still exist
      const getRes = await request(app)
        .get(`/api/posts/${postId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(getRes.status).toBe(200);
    });
  });
});

describe('POST /api/posts/:id/like', () => {
  let authToken;
  let postId;

  beforeEach(async () => {
    const { token } = await createAuthenticatedUser();
    authToken = token;

    const createRes = await request(app)
      .post('/api/posts')
      .set('Authorization', `Bearer ${authToken}`)
      .send(postFixtures.validPost);

    postId = createRes.body.id;
  });

  test('should toggle like on', async () => {
    const res = await request(app)
      .post(`/api/posts/${postId}/like`)
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.status).toBe(200);
    expect(res.body.liked).toBe(true);
    expect(res.body.likes).toBe(1);
  });

  test('should toggle like off', async () => {
    // Like first
    await request(app)
      .post(`/api/posts/${postId}/like`)
      .set('Authorization', `Bearer ${authToken}`);

    // Unlike
    const res = await request(app)
      .post(`/api/posts/${postId}/like`)
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.status).toBe(200);
    expect(res.body.liked).toBe(false);
    expect(res.body.likes).toBe(0);
  });
});
