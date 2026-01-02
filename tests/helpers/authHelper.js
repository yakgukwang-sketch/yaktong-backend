const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { pool } = require('../../server');

const JWT_SECRET = process.env.JWT_SECRET || 'yaktong-secret-key-2024';

/**
 * Create a test user in the database
 */
async function createTestUser(data = {}) {
  const {
    email = 'test@yaktong.com',
    password = 'password123',
    name = 'TestUser',
    isAdmin = false
  } = data;

  const hashedPassword = await bcrypt.hash(password, 10);

  const result = await pool.query(
    `INSERT INTO users (email, password, name, is_admin, email_verified)
     VALUES ($1, $2, $3, $4, true)
     RETURNING id, email, name, is_admin`,
    [email, hashedPassword, name, isAdmin]
  );

  return result.rows[0];
}

/**
 * Generate a JWT token for a user
 */
function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
}

/**
 * Create a test user and return both user data and auth token
 */
async function createAuthenticatedUser(data = {}) {
  const user = await createTestUser(data);
  const token = generateToken(user.id);
  return { user, token };
}

/**
 * Create an admin user with token
 */
async function createAdminUser(data = {}) {
  return createAuthenticatedUser({ ...data, isAdmin: true });
}

module.exports = {
  createTestUser,
  generateToken,
  createAuthenticatedUser,
  createAdminUser,
  JWT_SECRET
};
