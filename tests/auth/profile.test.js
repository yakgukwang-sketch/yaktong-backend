const request = require('supertest');
const { app } = require('../../server');
const { createAuthenticatedUser } = require('../helpers/authHelper');

describe('GET /api/auth/me', () => {
  let authToken;
  let testUser;

  beforeEach(async () => {
    const { user, token } = await createAuthenticatedUser();
    authToken = token;
    testUser = user;
  });

  test('should return user profile with valid token', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('email');
    expect(res.body).toHaveProperty('name');
    expect(res.body.email).toBe(testUser.email);
    expect(res.body).not.toHaveProperty('password');
  });

  test('should reject request without token (401)', async () => {
    const res = await request(app)
      .get('/api/auth/me');

    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty('message');
  });

  test('should reject request with invalid token (401)', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer invalid-token-here');

    expect(res.status).toBe(401);
  });

  test('should reject request with malformed authorization header', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'InvalidFormat');

    expect(res.status).toBe(401);
  });

  test('should return admin status correctly', async () => {
    const { token: adminToken } = await createAuthenticatedUser({
      email: 'admin@yaktong.com',
      isAdmin: true
    });

    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body.is_admin).toBe(true);
  });
});

describe('POST /api/auth/change-password', () => {
  let authToken;

  beforeEach(async () => {
    const { token } = await createAuthenticatedUser({
      password: 'oldpassword123'
    });
    authToken = token;
  });

  test('should change password with valid current password', async () => {
    const res = await request(app)
      .post('/api/auth/change-password')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        currentPassword: 'oldpassword123',
        newPassword: 'newpassword123'
      });

    expect(res.status).toBe(200);
  });

  test('should reject with wrong current password', async () => {
    const res = await request(app)
      .post('/api/auth/change-password')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        currentPassword: 'wrongpassword',
        newPassword: 'newpassword123'
      });

    expect(res.status).toBe(401);
  });

  test('should reject without authentication', async () => {
    const res = await request(app)
      .post('/api/auth/change-password')
      .send({
        currentPassword: 'oldpassword123',
        newPassword: 'newpassword123'
      });

    expect(res.status).toBe(401);
  });
});

describe('POST /api/auth/nickname', () => {
  let authToken;

  beforeEach(async () => {
    const { token } = await createAuthenticatedUser();
    authToken = token;
  });

  test('should update nickname', async () => {
    const res = await request(app)
      .post('/api/auth/nickname')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ nickname: 'NewNickname' });

    expect(res.status).toBe(200);

    // Verify the change
    const profileRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${authToken}`);

    expect(profileRes.body.name).toBe('NewNickname');
  });

  test('should reject without authentication', async () => {
    const res = await request(app)
      .post('/api/auth/nickname')
      .send({ nickname: 'NewNickname' });

    expect(res.status).toBe(401);
  });
});
