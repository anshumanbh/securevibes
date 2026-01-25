/**
 * Secure Express application for eval testing.
 * 
 * This application demonstrates SECURE patterns that should
 * NOT trigger false positives in SecureVibes.
 */

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { getUser, searchUsers } = require('./database');

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100
});
app.use(limiter);

/**
 * Get user by ID - SECURE implementation
 * Uses parameterized queries
 */
app.get('/users/:id', async (req, res) => {
  try {
    const userId = parseInt(req.params.id, 10);
    
    if (isNaN(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    // SECURE: Uses parameterized query (see database.js)
    const user = await getUser(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Don't expose password
    const { password, ...safeUser } = user;
    res.json(safeUser);
    
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * Search users - SECURE implementation
 * Uses parameterized queries with proper escaping
 */
app.get('/search', async (req, res) => {
  try {
    const { name } = req.query;
    
    if (!name || typeof name !== 'string') {
      return res.status(400).json({ error: 'Name parameter required' });
    }
    
    // Input validation
    if (name.length > 100) {
      return res.status(400).json({ error: 'Name too long' });
    }
    
    // SECURE: Uses parameterized query (see database.js)
    const users = await searchUsers(name);
    
    // Don't expose passwords
    const safeUsers = users.map(({ password, ...user }) => user);
    res.json(safeUsers);
    
  } catch (err) {
    console.error('Error searching users:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
