const { pool, initDB } = require('../server');

// Initialize test database before all tests
beforeAll(async () => {
  await initDB();
});

// Clean up test data before each test
beforeEach(async () => {
  // Delete in order due to foreign key constraints
  await pool.query('DELETE FROM comment_likes');
  await pool.query('DELETE FROM comment_dislikes');
  await pool.query('DELETE FROM comments');
  await pool.query('DELETE FROM post_likes');
  await pool.query('DELETE FROM post_dislikes');
  await pool.query('DELETE FROM posts');
  await pool.query('DELETE FROM job_likes');
  await pool.query('DELETE FROM jobs');
  await pool.query('DELETE FROM pharmacy_likes');
  await pool.query('DELETE FROM pharmacies');
  await pool.query('DELETE FROM notifications');
  await pool.query('DELETE FROM blocked_users');
  await pool.query('DELETE FROM reputation_votes');
  await pool.query('DELETE FROM license_verifications');
  await pool.query('DELETE FROM notices');
  await pool.query('DELETE FROM users');
});

// Close database connection after all tests
afterAll(async () => {
  await pool.end();
});

module.exports = { pool };
