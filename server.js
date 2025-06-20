// backend/server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const app = express();
const PORT = 3000;

app.use(cors());

app.get('/check', async (req, res) => {
  const token = req.query.address;

  if (!token) return res.status(400).json({ error: 'Missing token address' });

  try {
    const { data } = await axios.get(
      `https://api.honeypot.is/v2/IsHoneypot?address=${token}&network=bsc`
    );
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Honeypot API request failed', details: err.message });
  }
});

app.listen(PORT, () => console.log(`✅ Backend running at http://localhost:${PORT}`));
