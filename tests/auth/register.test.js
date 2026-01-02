const request = require('supertest');
const { app } = require('../../server');
const { userFixtures } = require('../helpers/fixtures');

describe('POST /api/auth/register', () => {
  test('should register a new user with valid data', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send(userFixtures.validUser);

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('token');
    expect(res.body).toHaveProperty('user');
    expect(res.body.user.email).toBe(userFixtures.validUser.email);
    expect(res.body.user.name).toBe(userFixtures.validUser.name);
    expect(res.body.user).not.toHaveProperty('password');
  });

  test('should reject duplicate email', async () => {
    // First registration
    await request(app)
      .post('/api/auth/register')
      .send(userFixtures.validUser);

    // Duplicate attempt
    const res = await request(app)
      .post('/api/auth/register')
      .send(userFixtures.validUser);

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('message');
  });

  test('should reject missing email', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        password: 'password123',
        name: 'TestUser'
      });

    expect(res.status).toBe(400);
  });

  test('should reject missing password', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        email: 'test@yaktong.com',
        name: 'TestUser'
      });

    expect(res.status).toBe(400);
  });

  test('should reject missing name', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        email: 'test@yaktong.com',
        password: 'password123'
      });

    expect(res.status).toBe(400);
  });

  test('should make first user admin', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send(userFixtures.validUser);

    expect(res.status).toBe(201);
    expect(res.body.user.is_admin).toBe(true);
  });

  test('should not make second user admin', async () => {
    // First user (becomes admin)
    await request(app)
      .post('/api/auth/register')
      .send(userFixtures.validUser);

    // Second user (should not be admin)
    const res = await request(app)
      .post('/api/auth/register')
      .send(userFixtures.secondUser);

    expect(res.status).toBe(201);
    expect(res.body.user.is_admin).toBe(false);
  });
});
