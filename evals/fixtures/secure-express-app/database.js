/**
 * Secure database module demonstrating proper SQL practices.
 * 
 * All queries use parameterized statements - NOT vulnerable to SQL injection.
 * SecureVibes should NOT flag these as vulnerabilities.
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'users.db');

/**
 * Get database connection
 */
function getDb() {
  return new sqlite3.Database(dbPath);
}

/**
 * Get user by ID - SECURE parameterized query
 * 
 * @param {number} userId - User ID to fetch
 * @returns {Promise<Object|null>} User object or null
 */
function getUser(userId) {
  return new Promise((resolve, reject) => {
    const db = getDb();
    
    // SECURE: Parameterized query - the ? placeholder prevents SQL injection
    // The userId is passed as a separate parameter, not concatenated
    db.get(
      'SELECT id, name, email, created_at FROM users WHERE id = ?',
      [userId],
      (err, row) => {
        db.close();
        if (err) reject(err);
        else resolve(row || null);
      }
    );
  });
}

/**
 * Search users by name - SECURE parameterized query
 * 
 * @param {string} searchTerm - Name to search for
 * @returns {Promise<Array>} Matching users
 */
function searchUsers(searchTerm) {
  return new Promise((resolve, reject) => {
    const db = getDb();
    
    // SECURE: Parameterized LIKE query
    // The % wildcards are added in JavaScript, then the whole term is parameterized
    // This prevents SQL injection while still allowing LIKE functionality
    const likePattern = `%${searchTerm}%`;
    
    db.all(
      'SELECT id, name, email, created_at FROM users WHERE name LIKE ?',
      [likePattern],
      (err, rows) => {
        db.close();
        if (err) reject(err);
        else resolve(rows || []);
      }
    );
  });
}

/**
 * Create user - SECURE parameterized INSERT
 * 
 * @param {Object} user - User data
 * @returns {Promise<number>} New user ID
 */
function createUser({ name, email, passwordHash }) {
  return new Promise((resolve, reject) => {
    const db = getDb();
    
    // SECURE: Parameterized INSERT
    db.run(
      'INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, datetime("now"))',
      [name, email, passwordHash],
      function(err) {
        db.close();
        if (err) reject(err);
        else resolve(this.lastID);
      }
    );
  });
}

/**
 * Update user - SECURE parameterized UPDATE
 * 
 * @param {number} userId - User ID to update
 * @param {Object} updates - Fields to update
 * @returns {Promise<boolean>} Success status
 */
function updateUser(userId, { name, email }) {
  return new Promise((resolve, reject) => {
    const db = getDb();
    
    // SECURE: Parameterized UPDATE with multiple parameters
    db.run(
      'UPDATE users SET name = ?, email = ? WHERE id = ?',
      [name, email, userId],
      function(err) {
        db.close();
        if (err) reject(err);
        else resolve(this.changes > 0);
      }
    );
  });
}

/**
 * Initialize database schema
 */
function initDb() {
  return new Promise((resolve, reject) => {
    const db = getDb();
    
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `, (err) => {
      db.close();
      if (err) reject(err);
      else resolve();
    });
  });
}

module.exports = {
  getUser,
  searchUsers,
  createUser,
  updateUser,
  initDb
};
