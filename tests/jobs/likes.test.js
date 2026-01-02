const request = require('supertest');
const { app } = require('../../server');
const { createAuthenticatedUser } = require('../helpers/authHelper');
const { jobFixtures } = require('../helpers/fixtures');

describe('Jobs Like API', () => {
  let authToken;
  let jobId;

  beforeEach(async () => {
    const { token } = await createAuthenticatedUser();
    authToken = token;

    const createRes = await request(app)
      .post('/api/jobs')
      .set('Authorization', `Bearer ${authToken}`)
      .send(jobFixtures.hiringJob);

    jobId = createRes.body.id;
  });

  describe('POST /api/jobs/:id/like', () => {
    test('should toggle like on', async () => {
      const res = await request(app)
        .post(`/api/jobs/${jobId}/like`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.liked).toBe(true);
    });

    test('should toggle like off', async () => {
      // Like first
      await request(app)
        .post(`/api/jobs/${jobId}/like`)
        .set('Authorization', `Bearer ${authToken}`);

      // Unlike
      const res = await request(app)
        .post(`/api/jobs/${jobId}/like`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.liked).toBe(false);
    });

    test('should require authentication', async () => {
      const res = await request(app)
        .post(`/api/jobs/${jobId}/like`);

      expect(res.status).toBe(401);
    });
  });

  describe('GET /api/jobs/liked/list', () => {
    test('should return empty liked list initially', async () => {
      const res = await request(app)
        .get('/api/jobs/liked/list')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBe(0);
    });

    test('should return liked jobs', async () => {
      // Like the job
      await request(app)
        .post(`/api/jobs/${jobId}/like`)
        .set('Authorization', `Bearer ${authToken}`);

      const res = await request(app)
        .get('/api/jobs/liked/list')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.length).toBe(1);
      expect(res.body[0].id).toBe(jobId);
      expect(res.body[0].is_liked).toBe(true);
    });

    test('should not include unliked jobs', async () => {
      // Like then unlike
      await request(app)
        .post(`/api/jobs/${jobId}/like`)
        .set('Authorization', `Bearer ${authToken}`);

      await request(app)
        .post(`/api/jobs/${jobId}/like`)
        .set('Authorization', `Bearer ${authToken}`);

      const res = await request(app)
        .get('/api/jobs/liked/list')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.length).toBe(0);
    });
  });

  describe('POST /api/jobs/:id/bump', () => {
    test('should bump own job listing', async () => {
      const res = await request(app)
        .post(`/api/jobs/${jobId}/bump`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
    });
  });

  describe('POST /api/jobs/:id/complete', () => {
    test('should toggle job completion status', async () => {
      const res = await request(app)
        .post(`/api/jobs/${jobId}/complete`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.is_completed).toBe(true);

      // Toggle back
      const res2 = await request(app)
        .post(`/api/jobs/${jobId}/complete`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res2.body.is_completed).toBe(false);
    });
  });
});
