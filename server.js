// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const axios = require('axios');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const { OAuth2Client } = require('google-auth-library'); // ✅ added for Google OAuth
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/echoscribe', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  phone: { type: String, unique: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Transcription Schema
const transcriptionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Transcription = mongoose.model('Transcription', transcriptionSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Multer Configuration for Audio Upload
const upload = multer({ storage: multer.memoryStorage() });

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// ==================== AUTH ROUTES ====================

// Sign Up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'All fields are required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      token,
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword)
      return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ==================== GOOGLE OAUTH ROUTES ====================

// GET /api/auth/google
app.get('/api/auth/google', (req, res) => {
  res.json({ message: 'Google OAuth endpoint ready' });
});

// POST /api/auth/google/callback
app.post('/api/auth/google/callback', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Google token required' });

    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    let user = await User.findOne({ email: payload.email });
    if (!user) {
      user = new User({
        name: payload.name,
        email: payload.email,
        password: '', // not needed for Google login
      });
      await user.save();
    }

    const jwtToken = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token: jwtToken,
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Google OAuth error:', error);
    res.status(500).json({ error: 'Google authentication failed' });
  }
});

// ==================== PHONE AUTH ROUTES ====================

// Temporary in-memory store for OTPs
const otpStore = new Map();

// POST /api/auth/send-otp
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set(phone, otp);

    // Simulate sending OTP (integrate Twilio or similar in production)
    console.log(`📲 OTP for ${phone}: ${otp}`);

    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// POST /api/auth/verify-otp
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp)
      return res.status(400).json({ error: 'Phone and OTP required' });

    const storedOtp = otpStore.get(phone);
    if (storedOtp !== otp)
      return res.status(401).json({ error: 'Invalid or expired OTP' });

    otpStore.delete(phone);

    let user = await User.findOne({ phone });
    if (!user) {
      user = new User({
        name: 'User ' + phone.slice(-4),
        email: `${phone}@echoscribe.app`,
        password: '',
        phone
      });
      await user.save();
    }

    const token = jwt.sign(
      { id: user._id, phone: user.phone },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: { id: user._id, name: user.name, phone: user.phone }
    });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

// ==================== TRANSCRIPTION ROUTES ====================

app.post('/api/transcribe', authenticateToken, upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No audio file provided' });

    const DEEPGRAM_API_KEY = process.env.DEEPGRAM_API_KEY;
    if (!DEEPGRAM_API_KEY)
      return res.status(500).json({ error: 'Deepgram API key not configured' });

    const response = await axios.post(
      'https://api.deepgram.com/v1/listen',
      req.file.buffer,
      {
        headers: {
          'Authorization': `Token ${DEEPGRAM_API_KEY}`,
          'Content-Type': req.file.mimetype
        },
        params: { model: 'nova-2', smart_format: true }
      }
    );

    const transcript = response.data.results.channels[0].alternatives[0].transcript;
    if (!transcript) return res.status(400).json({ error: 'No speech detected in audio' });

    res.json({ transcript });
  } catch (error) {
    console.error('Transcription error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Transcription failed', details: error.response?.data?.error || error.message });
  }
});

app.get('/api/history', authenticateToken, async (req, res) => {
  try {
    const transcriptions = await Transcription.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(transcriptions);
  } catch (error) {
    console.error('Fetch history error:', error);
    res.status(500).json({ error: 'Error fetching history' });
  }
});

app.post('/api/history', authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim())
      return res.status(400).json({ error: 'Text is required' });

    const transcription = new Transcription({ userId: req.user.id, text: text.trim() });
    await transcription.save();
    res.status(201).json(transcription);
  } catch (error) {
    console.error('Save transcription error:', error);
    res.status(500).json({ error: 'Error saving transcription' });
  }
});

app.delete('/api/history/:id', authenticateToken, async (req, res) => {
  try {
    const transcription = await Transcription.findOne({ _id: req.params.id, userId: req.user.id });
    if (!transcription) return res.status(404).json({ error: 'Transcription not found' });

    await transcription.deleteOne();
    res.json({ message: 'Transcription deleted' });
  } catch (error) {
    console.error('Delete transcription error:', error);
    res.status(500).json({ error: 'Error deleting transcription' });
  }
});

app.delete('/api/history', authenticateToken, async (req, res) => {
  try {
    await Transcription.deleteMany({ userId: req.user.id });
    res.json({ message: 'All transcriptions deleted' });
  } catch (error) {
    console.error('Delete all error:', error);
    res.status(500).json({ error: 'Error deleting transcriptions' });
  }
});

app.get('/api/history/download', authenticateToken, async (req, res) => {
  try {
    const format = req.query.format || 'pdf';
    const transcriptions = await Transcription.find({ userId: req.user.id }).sort({ createdAt: -1 });

    if (format === 'pdf') {
      const doc = new PDFDocument();
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'attachment; filename=transcriptions.pdf');
      doc.pipe(res);

      doc.fontSize(20).text('EchoScribe Transcriptions', { align: 'center' });
      doc.moveDown();

      transcriptions.forEach((item, index) => {
        doc.fontSize(12).text(`${index + 1}. ${new Date(item.createdAt).toLocaleString()}`);
        doc.fontSize(10).text(item.text);
        doc.moveDown();
      });

      doc.end();
    } else if (format === 'txt') {
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', 'attachment; filename=transcriptions.txt');
      let content = 'EchoScribe Transcriptions\n\n';
      transcriptions.forEach((item, index) => {
        content += `${index + 1}. ${new Date(item.createdAt).toLocaleString()}\n`;
        content += `${item.text}\n\n`;
      });
      res.send(content);
    } else {
      res.status(400).json({ error: 'Invalid format. Use pdf or txt' });
    }
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Error generating download' });
  }
});

// ==================== SERVER START ====================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 API available at http://localhost:${PORT}`);
});
