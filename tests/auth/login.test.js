const request = require('supertest');
const { app } = require('../../server');
const { createTestUser } = require('../helpers/authHelper');
const { userFixtures } = require('../helpers/fixtures');

describe('POST /api/auth/login', () => {
  beforeEach(async () => {
    // Create test user before each login test
    await createTestUser(userFixtures.validUser);
  });

  test('should login with valid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: userFixtures.validUser.email,
        password: userFixtures.validUser.password
      });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('token');
    expect(res.body).toHaveProperty('user');
    expect(res.body.user.email).toBe(userFixtures.validUser.email);
  });

  test('should reject invalid password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: userFixtures.validUser.email,
        password: 'wrongpassword'
      });

    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('message');
  });

  test('should reject non-existent email', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'nonexistent@yaktong.com',
        password: 'password123'
      });

    expect(res.status).toBe(401);
  });

  test('should reject missing email', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        password: 'password123'
      });

    expect(res.status).toBe(400);
  });

  test('should reject missing password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: userFixtures.validUser.email
      });

    expect(res.status).toBe(400);
  });

  test('should return JWT token in correct format', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: userFixtures.validUser.email,
        password: userFixtures.validUser.password
      });

    expect(res.status).toBe(200);
    expect(typeof res.body.token).toBe('string');
    // JWT token has 3 parts separated by dots
    expect(res.body.token.split('.').length).toBe(3);
  });
});
