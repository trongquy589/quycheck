// backend/server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const axios = require('axios');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// Register
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const hash = await bcrypt.hash(password, 10);
  try {
    await db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hash]);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: 'User may already exist', details: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
  if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
  const match = await bcrypt.compare(password, rows[0].password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: rows[0].id, email }, process.env.JWT_SECRET);
  res.json({ token });
});

// Protected route: check + save
app.post('/api/check', async (req, res) => {
  const token = req.body.token;
  const auth = req.headers.authorization;
  if (!token || !auth) return res.status(400).json({ error: 'Missing token or auth' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    const { data } = await axios.get('https://api.honeypot.is/v2/IsHoneypot', {
      params: { address: token, chainID: 56 },
    });
    await db.query('INSERT INTO token_history (user_id, token_address, result) VALUES (?, ?, ?)', [
      decoded.id,
      token,
      JSON.stringify(data),
    ]);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Check failed', details: err.message });
  }
});

// Get history
app.get('/api/history', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    const [rows] = await db.query('SELECT * FROM token_history WHERE user_id = ? ORDER BY created_at DESC', [decoded.id]);
    res.json(rows);
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized', details: err.message });
  }
});

app.listen(PORT, () => console.log(`✅ Backend running on port ${PORT}`));
