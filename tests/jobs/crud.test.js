const request = require('supertest');
const { app } = require('../../server');
const { createAuthenticatedUser } = require('../helpers/authHelper');
const { jobFixtures } = require('../helpers/fixtures');

describe('Jobs CRUD', () => {
  let authToken;
  let userId;

  beforeEach(async () => {
    const { user, token } = await createAuthenticatedUser();
    authToken = token;
    userId = user.id;
  });

  describe('GET /api/jobs', () => {
    test('should return empty jobs list initially', async () => {
      const res = await request(app)
        .get('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBe(0);
    });

    test('should return jobs after creation', async () => {
      await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobFixtures.hiringJob);

      const res = await request(app)
        .get('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.length).toBe(1);
      expect(res.body[0].title).toBe(jobFixtures.hiringJob.title);
    });

    test('should filter by type', async () => {
      await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobFixtures.hiringJob);

      await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobFixtures.seekingJob);

      const res = await request(app)
        .get('/api/jobs?type=hiring')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.length).toBe(1);
      expect(res.body[0].type).toBe('hiring');
    });

    test('should filter by work type', async () => {
      await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobFixtures.hiringJob); // 풀타임

      await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobFixtures.seekingJob); // 파트타임

      const res = await request(app)
        .get('/api/jobs?workType=풀타임')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.length).toBe(1);
      expect(res.body[0].work_type).toBe('풀타임');
    });

    test('should require authentication', async () => {
      const res = await request(app)
        .get('/api/jobs');

      expect(res.status).toBe(401);
    });
  });

  describe('POST /api/jobs', () => {
    test('should create a hiring job post', async () => {
      const res = await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobFixtures.hiringJob);

      expect(res.status).toBe(201);
      expect(res.body.title).toBe(jobFixtures.hiringJob.title);
      expect(res.body.type).toBe('hiring');
      expect(res.body.author_id).toBe(userId);
    });

    test('should create a seeking job post', async () => {
      const res = await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobFixtures.seekingJob);

      expect(res.status).toBe(201);
      expect(res.body.type).toBe('seeking');
    });

    test('should reject without title', async () => {
      const { title, ...jobWithoutTitle } = jobFixtures.hiringJob;

      const res = await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobWithoutTitle);

      expect(res.status).toBe(400);
    });

    test('should reject without authentication', async () => {
      const res = await request(app)
        .post('/api/jobs')
        .send(jobFixtures.hiringJob);

      expect(res.status).toBe(401);
    });
  });

  describe('GET /api/jobs/:id', () => {
    test('should return job details', async () => {
      const createRes = await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobFixtures.hiringJob);

      const jobId = createRes.body.id;

      const res = await request(app)
        .get(`/api/jobs/${jobId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.id).toBe(jobId);
      expect(res.body.title).toBe(jobFixtures.hiringJob.title);
    });

    test('should return 404 for non-existent job', async () => {
      const res = await request(app)
        .get('/api/jobs/99999')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(404);
    });
  });

  describe('PUT /api/jobs/:id', () => {
    test('should update own job post', async () => {
      const createRes = await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobFixtures.hiringJob);

      const jobId = createRes.body.id;

      const res = await request(app)
        .put(`/api/jobs/${jobId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          ...jobFixtures.hiringJob,
          title: '수정된 제목'
        });

      expect(res.status).toBe(200);
      expect(res.body.title).toBe('수정된 제목');
    });

    test('should not update other user job', async () => {
      const createRes = await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobFixtures.hiringJob);

      const jobId = createRes.body.id;

      // Create another user
      const { token: otherToken } = await createAuthenticatedUser({
        email: 'other@yaktong.com'
      });

      const res = await request(app)
        .put(`/api/jobs/${jobId}`)
        .set('Authorization', `Bearer ${otherToken}`)
        .send({
          ...jobFixtures.hiringJob,
          title: '수정된 제목'
        });

      // Should return 200 but not update (no rows affected)
      expect(res.status).toBe(200);

      // Verify original title
      const getRes = await request(app)
        .get(`/api/jobs/${jobId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(getRes.body.title).toBe(jobFixtures.hiringJob.title);
    });
  });

  describe('DELETE /api/jobs/:id', () => {
    test('should delete own job post', async () => {
      const createRes = await request(app)
        .post('/api/jobs')
        .set('Authorization', `Bearer ${authToken}`)
        .send(jobFixtures.hiringJob);

      const jobId = createRes.body.id;

      const res = await request(app)
        .delete(`/api/jobs/${jobId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);

      // Verify deletion
      const getRes = await request(app)
        .get(`/api/jobs/${jobId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(getRes.status).toBe(404);
    });
  });
});
