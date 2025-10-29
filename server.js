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
const { OAuth2Client } = require('google-auth-library');
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

// User Schema - UPDATED to include hasPassword field
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: false },
  hasPassword: { type: Boolean, default: true }, // ✅ NEW: Track if user has set a password
  profilePhoto: { type: String, required: false }, // ✅ NEW: Store Google profile photo
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

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ==================== AUTH ROUTES ====================

// Sign Up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
      hasPassword: true // ✅ User signing up with email/password has a password
    });

    await user.save();

    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        hasPassword: user.hasPassword,
        profilePhoto: user.profilePhoto
      }
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

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if user has a password set
    if (!user.hasPassword || !user.password) {
      return res.status(401).json({ error: 'Please sign in with Google or set a password first' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        hasPassword: user.hasPassword,
        profilePhoto: user.profilePhoto
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ==================== PASSWORD MANAGEMENT ROUTES ====================

// ✅ NEW: Set Password (for Google OAuth users)
app.put('/api/auth/set-password', authenticateToken, async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword) {
      return res.status(400).json({ error: 'New password is required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if user already has a password
    if (user.hasPassword && user.password) {
      return res.status(400).json({ error: 'Password already set. Use change password instead.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.hasPassword = true;
    await user.save();

    res.json({
      message: 'Password set successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        hasPassword: user.hasPassword,
        profilePhoto: user.profilePhoto
      }
    });
  } catch (error) {
    console.error('Set password error:', error);
    res.status(500).json({ error: 'Server error while setting password' });
  }
});

// ✅ UPDATED: Change Password (for users with existing passwords)
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if user has a password set
    if (!user.hasPassword || !user.password) {
      return res.status(400).json({ error: 'No password set. Use set password instead.' });
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash and save new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({
      message: 'Password changed successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        hasPassword: user.hasPassword,
        profilePhoto: user.profilePhoto
      }
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Server error while changing password' });
  }
});

// ==================== GOOGLE OAUTH ROUTES ====================

app.get('/api/auth/google', (req, res) => {
  const redirectUri = `${process.env.BACKEND_URL || 'http://localhost:5000'}/api/auth/google/callback`;
  const googleAuthUrl =
    `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${process.env.GOOGLE_CLIENT_ID}&` +
    `redirect_uri=${redirectUri}&` +
    `response_type=code&` +
    `scope=profile email&` +
    `access_type=offline&` +
    `prompt=consent`;

  res.redirect(googleAuthUrl);
});

app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) {
      return res.send('<script>window.close();</script>');
    }

    const redirectUri = `${process.env.BACKEND_URL || 'http://localhost:5000'}/api/auth/google/callback`;
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    });

    const { id_token } = tokenResponse.data;

    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    const ticket = await client.verifyIdToken({
      idToken: id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    let user = await User.findOne({ email: payload.email });
    if (!user) {
      // ✅ NEW: Create user with hasPassword = false for Google OAuth
      user = new User({
        name: payload.name,
        email: payload.email,
        password: '', // No password for Google OAuth users initially
        hasPassword: false, // ✅ Mark that user doesn't have a password yet
        profilePhoto: payload.picture || '' // ✅ Store Google profile photo
      });
      await user.save();
    }

    const jwtToken = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // ✅ UPDATED: Include hasPassword and profilePhoto in user data
    const userData = {
      id: user._id,
      name: user.name,
      email: user.email,
      hasPassword: user.hasPassword,
      profilePhoto: user.profilePhoto
    };

    res.send(`
      <script>
        window.opener.postMessage(
          { token: '${jwtToken}', user: ${JSON.stringify(userData)} },
          '${process.env.FRONTEND_URL || 'http://localhost:3000'}'
        );
        window.close();
      </script>
    `);
  } catch (error) {
    console.error('Google OAuth callback error:', error);
    res.send('<script>alert("Authentication failed"); window.close();</script>');
  }
});

// ==================== TRANSCRIPTION ROUTES ====================

app.post('/api/transcribe', authenticateToken, upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No audio file provided' });
    }

    const DEEPGRAM_API_KEY = process.env.DEEPGRAM_API_KEY;
    if (!DEEPGRAM_API_KEY) {
      return res.status(500).json({ error: 'Deepgram API key not configured' });
    }

    const response = await axios.post(
      'https://api.deepgram.com/v1/listen',
      req.file.buffer,
      {
        headers: {
          'Authorization': `Token ${DEEPGRAM_API_KEY}`,
          'Content-Type': req.file.mimetype
        },
        params: {
          model: 'nova-2',
          smart_format: true
        }
      }
    );

    const transcript = response.data.results.channels[0].alternatives[0].transcript;

    if (!transcript) {
      return res.status(400).json({ error: 'No speech detected in audio' });
    }

    res.json({ transcript });
  } catch (error) {
    console.error('Transcription error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Transcription failed',
      details: error.response?.data?.error || error.message
    });
  }
});

// ==================== TRANSLATION ROUTE ====================

app.post('/api/translate', authenticateToken, async (req, res) => {
  try {
    const { text, targetLanguage } = req.body;

    // Validate input
    if (!text || !text.trim()) {
      return res.status(400).json({ error: 'Text is required for translation' });
    }

    if (!targetLanguage) {
      return res.status(400).json({ error: 'Target language is required' });
    }

    // Validate target language (Indian languages supported)
    const supportedLanguages = ['hi', 'mr', 'bn', 'gu', 'ta', 'te', 'kn', 'ml', 'pa', 'ur'];
    if (!supportedLanguages.includes(targetLanguage)) {
      return res.status(400).json({ 
        error: 'Unsupported target language',
        supportedLanguages: supportedLanguages 
      });
    }

    // Get MyMemory API key from environment or use default
    const MYMEMORY_API_KEY = process.env.MYMEMORY_API_KEY || '2f1d0cbe7843b300e9ce';
    
    // Build API URL with your API key
    const apiUrl = `https://api.mymemory.translated.net/get?q=${encodeURIComponent(text)}&langpair=en|${targetLanguage}&de=${MYMEMORY_API_KEY}`;
    
    // Make request to MyMemory API
    const response = await axios.get(apiUrl);
    
    // Check response status
    if (response.data.responseStatus === 200 && response.data.responseData) {
      const translatedText = response.data.responseData.translatedText;
      
      // Log successful translation
      console.log(`✅ Translation completed: en -> ${targetLanguage} (${text.length} chars)`);
      
      res.json({
        translatedText: translatedText,
        sourceLanguage: 'en',
        targetLanguage: targetLanguage,
        matches: response.data.matches?.length || 0, // Translation quality indicator
        originalText: text
      });
    } else if (response.data.responseStatus === 403) {
      console.error('❌ MyMemory API quota exceeded');
      res.status(403).json({ 
        error: 'Translation API quota exceeded. Please try again later.',
        details: 'Daily limit reached for your API key'
      });
    } else if (response.data.responseStatus === 429) {
      console.error('❌ MyMemory API rate limit hit');
      res.status(429).json({ 
        error: 'Too many translation requests. Please wait a moment.',
        details: 'Rate limit exceeded'
      });
    } else {
      console.error('❌ MyMemory API error:', response.data);
      res.status(500).json({ 
        error: 'Translation service returned an error',
        details: response.data.responseDetails || 'Unknown error'
      });
    }
  } catch (error) {
    console.error('Translation error:', error.response?.data || error.message);
    
    // Handle specific error cases
    if (error.response?.status === 403) {
      res.status(403).json({ 
        error: 'Translation API quota exceeded',
        details: 'Please check your API key or wait for quota reset'
      });
    } else if (error.response?.status === 429) {
      res.status(429).json({ 
        error: 'Too many translation requests. Please wait a moment.',
        details: 'Rate limit exceeded'
      });
    } else if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
      res.status(504).json({ 
        error: 'Translation request timed out',
        details: 'Please try again with shorter text'
      });
    } else {
      res.status(500).json({
        error: 'Translation failed',
        details: error.message
      });
    }
  }
});

// ==================== HISTORY & DOWNLOAD ROUTES ====================

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
    if (!text || !text.trim()) {
      return res.status(400).json({ error: 'Text is required' });
    }

    const transcription = new Transcription({
      userId: req.user.id,
      text: text.trim()
    });

    await transcription.save();
    res.status(201).json(transcription);
  } catch (error) {
    console.error('Save transcription error:', error);
    res.status(500).json({ error: 'Error saving transcription' });
  }
});

app.delete('/api/history/:id', authenticateToken, async (req, res) => {
  try {
    const transcription = await Transcription.findOne({
      _id: req.params.id,
      userId: req.user.id
    });

    if (!transcription) {
      return res.status(404).json({ error: 'Transcription not found' });
    }

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
  console.log(`🌐 Translation API: MyMemory (API Key configured)`);
});
