const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const cors = require('cors');
const axios = require('axios');
const session = require('express-session');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const port = 3000;

let fetch;
(async () => {
  fetch = (await import('node-fetch')).default;
})();

async function sendEmailResend({ to, subject, html, text }) {
  if (!fetch) {
    fetch = (await import('node-fetch')).default;
  }
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'digitalmarketingecommerce662@gmail.com',
      to,
      subject,
      html,
      text,
    }),
  });
  const data = await response.json();
  return data;
}

// Middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// PostgreSQL setup
const pool = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
});

// Session setup
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'keyboard cat',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  })
);

function ensureLoggedIn(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  } else {
    return res.redirect('/?boterror=1');
  }
}

// Route: Signup
app.post('/signup', async (req, res) => {
  const { fullname, email, company, password } = req.body;
  if (!fullname || !email || !company || !password) {
    return res.send('<script>alert("All fields are required!"); window.location.href="/signup.html";</script>');
  }
  try {
    const checkUser = await pool.query('SELECT email FROM registration WHERE email = $1', [email]);
    if (checkUser.rows.length > 0) {
      return res.send('<script>alert("User already exists!"); window.location.href="/signup.html";</script>');
    }
    await pool.query(
      `INSERT INTO registration (fullname, email, company, password_hash)
       VALUES ($1, $2, $3, crypt($4, gen_salt('bf')))`,
      [fullname, email, company, password]
    );
    res.redirect('/?registered=1');
  } catch (err) {
    console.error('Signup Error:', err);
    res.status(500).send('Registration failed. Please try again.');
  }
});

// Route: Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    // Verify user by matching email and hashed password in DB
    const result = await pool.query(
      `SELECT email, password_hash FROM registration 
       WHERE email = $1 AND password_hash = crypt($2, password_hash)`,
      [username, password]
    );
    if (result.rows.length === 0) {
      return res.redirect('/?loginerror=1');
    }
    // After successful login check
    const passwordHash = result.rows[0].password_hash;
    await pool.query(
      `INSERT INTO loggedusers (email, password_hash, login_time)
       VALUES ($1, $2, CURRENT_TIMESTAMP)
       ON CONFLICT (email) DO UPDATE SET 
       password_hash = EXCLUDED.password_hash, login_time = EXCLUDED.login_time`,
      [username, passwordHash]
    );
    // Store session info
    req.session.userId = result.rows[0].email;
    req.session.user = {
      email: result.rows[0].email,
      fullname: result.rows[0].fullname,
    };
    res.redirect('/?loggedin=1');
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send('Server error');
  }
});

// Route: Contact Form
app.post('/contacts', async (req, res) => {
  const { name, email, message } = req.body;
  try {
    // Check if user exists
    const userExists = await pool.query('SELECT email FROM loggedusers WHERE email = $1', [email]);
    if (userExists.rows.length === 0) {
      return res.redirect('/?failed=1');
    }
    // Insert message into DB
    await pool.query('INSERT INTO contact_messages (name, email, message) VALUES ($1, $2, $3)', [name, email, message]);

    // Send confirmation email using Resend API via fetch
    await sendEmailResend({
      to: email,
      subject: 'Message Received - We Will Contact You Soon',
      html: `
        <p>Hi ${name},</p>
        <p>Thank you for reaching out! We've received your message:</p>
        <blockquote>${message}</blockquote>
        <p>We will contact you soon.</p>
        <br><p>Best regards,<br>Tech Digital Marketing</p>
      `,
      text: `Hi ${name},\n\nThank you for reaching out! We've received your message. We will contact you soon.`,
    });

    return res.redirect('/?success=1');
  } catch (err) {
    console.error('Contact error:', err);
    return res.redirect('/?failed=1');
  }
});

// Route: Send OTP for Forgot Password
app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000);
  req.session.otp = otp;
  req.session.otpEmail = email;

  try {
    // Send OTP email using Resend API via fetch
    await sendEmailResend({
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is: ${otp}`,
    });

    res.json({ message: 'OTP sent to your email.' });
  } catch (err) {
    console.error('OTP mail error:', err);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

// OTP verification
app.post('/api/verify-otp', (req, res) => {
  const { otp, email } = req.body;
  if (
    req.session.otp &&
    req.session.otpEmail === email &&
    String(req.session.otp) === String(otp)
  ) {
    req.session.otp = null;
    req.session.otpEmail = null;
    return res.json({ success: true });
  } else {
    return res.json({ success: false });
  }
});

// Password reset
app.post('/api/reset-password', async (req, res) => {
  const { email, password } = req.body;
  try {
    await pool.query(
      `UPDATE registration SET password_hash = crypt($1, gen_salt('bf')) WHERE email = $2`,
      [password, email]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Reset password error:', err);
    res.json({ success: false });
  }
});

// Profile info from DB
app.get('/api/profile', ensureLoggedIn, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT fullname, email FROM registration WHERE email = $1',
      [req.session.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Profile fetch error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/isloggedin', (req, res) => {
  res.json({ loggedIn: !!req.session.userId });
});

// Route: Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('Error logging out');
    res.redirect('/');
  });
});

// Route: Chatbot (Protected)
app.get('/chatbot', ensureLoggedIn, (req, res) => {
  res.sendFile(__dirname + '/public/CTA.html');
});

// Route: Gemini API Integration
app.post('/api/chat', ensureLoggedIn, async (req, res) => {
  const userMessage = req.body.message;
  if (!userMessage || typeof userMessage !== 'string') {
    return res.status(400).json({ error: 'Invalid message' });
  }
  try {
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=AIzaSyBAMpWgUJodpn1REJkbdtyYzcb_VLGe9ko`,
      {
        contents: [{ parts: [{ text: userMessage }] }],
      }
    );
    const botReply = response.data.candidates?.[0]?.content?.parts?.[0]?.text || "Sorry, I didn't understand that.";
    res.json({ reply: botReply });
  } catch (err) {
    console.error('Gemini API Error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to fetch reply from Gemini' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`✅ Server is running at: http://localhost:${port}`);
});
