const request = require('supertest');
const { app } = require('../../server');
const { createAuthenticatedUser } = require('../helpers/authHelper');
const { postFixtures, commentFixtures } = require('../helpers/fixtures');

describe('Comments API', () => {
  let authToken;
  let postId;

  beforeEach(async () => {
    const { token } = await createAuthenticatedUser();
    authToken = token;

    // Create a post first
    const createRes = await request(app)
      .post('/api/posts')
      .set('Authorization', `Bearer ${authToken}`)
      .send(postFixtures.validPost);

    postId = createRes.body.id;
  });

  describe('GET /api/posts/:postId/comments', () => {
    test('should return empty comments list initially', async () => {
      const res = await request(app)
        .get(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBe(0);
    });

    test('should return comments after creation', async () => {
      await request(app)
        .post(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(commentFixtures.validComment);

      const res = await request(app)
        .get(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.length).toBe(1);
      expect(res.body[0].content).toBe(commentFixtures.validComment.content);
    });

    test('should require authentication', async () => {
      const res = await request(app)
        .get(`/api/posts/${postId}/comments`);

      expect(res.status).toBe(401);
    });
  });

  describe('POST /api/posts/:postId/comments', () => {
    test('should create a new comment', async () => {
      const res = await request(app)
        .post(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(commentFixtures.validComment);

      expect(res.status).toBe(201);
      expect(res.body.content).toBe(commentFixtures.validComment.content);
      expect(res.body.post_id).toBe(postId);
    });

    test('should create a nested reply', async () => {
      // Create parent comment
      const parentRes = await request(app)
        .post(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(commentFixtures.validComment);

      const parentId = parentRes.body.id;

      // Create reply
      const res = await request(app)
        .post(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          ...commentFixtures.replyComment,
          parentId
        });

      expect(res.status).toBe(201);
      expect(res.body.parent_id).toBe(parentId);
    });

    test('should reject empty content', async () => {
      const res = await request(app)
        .post(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ content: '' });

      expect(res.status).toBe(400);
    });

    test('should reject without authentication', async () => {
      const res = await request(app)
        .post(`/api/posts/${postId}/comments`)
        .send(commentFixtures.validComment);

      expect(res.status).toBe(401);
    });
  });

  describe('DELETE /api/comments/:id', () => {
    test('should delete own comment', async () => {
      const createRes = await request(app)
        .post(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(commentFixtures.validComment);

      const commentId = createRes.body.id;

      const res = await request(app)
        .delete(`/api/comments/${commentId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);

      // Verify deletion
      const getRes = await request(app)
        .get(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(getRes.body.length).toBe(0);
    });

    test('should not delete other user comment', async () => {
      const createRes = await request(app)
        .post(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(commentFixtures.validComment);

      const commentId = createRes.body.id;

      // Create another user
      const { token: otherToken } = await createAuthenticatedUser({
        email: 'other@yaktong.com'
      });

      const res = await request(app)
        .delete(`/api/comments/${commentId}`)
        .set('Authorization', `Bearer ${otherToken}`);

      expect(res.status).toBe(200);

      // Comment should still exist
      const getRes = await request(app)
        .get(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(getRes.body.length).toBe(1);
    });
  });

  describe('POST /api/comments/:id/like', () => {
    let commentId;

    beforeEach(async () => {
      const createRes = await request(app)
        .post(`/api/posts/${postId}/comments`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(commentFixtures.validComment);

      commentId = createRes.body.id;
    });

    test('should toggle comment like on', async () => {
      const res = await request(app)
        .post(`/api/comments/${commentId}/like`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.liked).toBe(true);
    });

    test('should toggle comment like off', async () => {
      // Like first
      await request(app)
        .post(`/api/comments/${commentId}/like`)
        .set('Authorization', `Bearer ${authToken}`);

      // Unlike
      const res = await request(app)
        .post(`/api/comments/${commentId}/like`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.liked).toBe(false);
    });
  });
});
