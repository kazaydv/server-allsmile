// =============================================
// server.js — OTP Backend for Shopify + Sparrow SMS
// =============================================
// Setup:
//   npm init -y
//   npm install express cors
//   node server.js
// =============================================

const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

app.options('*', cors());
app.use(express.json());

// ── CONFIG — Replace these ────────────────────
const SPARROW_TOKEN  = 'v2_lBxZUNaLnXKKBH4B7Hz1Qv9cOY9.copp';   // From web.sparrowsms.com
const SPARROW_SENDER = 'Allsmile';          // Your approved Sender ID
const SPARROW_API    = 'https://api.sparrowsms.com/v2/sms/';
const OTP_EXPIRY_MS  = 5 * 60 * 1000;          // 5 minutes
const MAX_ATTEMPTS   = 5;
const PORT           = 3000;
// ─────────────────────────────────────────────

// In-memory OTP store
// Structure: { "98XXXXXXXX": { otp, expiry, attempts } }
// ⚠️  Use Redis in production for multi-server setups
const otpStore = {};

// ── Helper: Generate 6-digit OTP ─────────────
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ── Helper: Validate Nepal phone number ──────
function isValidPhone(phone) {
  return /^[0-9]{10}$/.test(phone);
}

// ─────────────────────────────────────────────
// ROUTE: POST /send-otp
// Body: { phone: "98XXXXXXXX" }
// ─────────────────────────────────────────────
app.post('/send-otp', async (req, res) => {
  const { phone } = req.body;

  if (!phone || !isValidPhone(phone)) {
    return res.status(400).json({
      success: false,
      error: 'Please enter a valid 10-digit phone number.'
    });
  }

  const otp = generateOtp();
  otpStore[phone] = {
    otp,
    expiry:   Date.now() + OTP_EXPIRY_MS,
    attempts: 0
  };

  const message = `Your Shopify verification code is ${otp}. Valid for 5 minutes. Do not share this code.`;

  const params = new URLSearchParams({
    token: SPARROW_TOKEN,
    from:  SPARROW_SENDER,
    to:    phone,
    text:  message
  });

  try {
    const response = await fetch(`${SPARROW_API}?${params.toString()}`);
    const data     = await response.json();

    if (data.response_code === 200) {
      console.log(`✅ OTP sent → ${phone} : ${otp}`);
      return res.json({ success: true, message: 'OTP sent successfully.' });
    } else {
      console.error(`❌ Sparrow error [${data.response_code}]:`, data.response);
      return res.status(500).json({
        success: false,
        error: data.response || 'Failed to send OTP. Please try again.'
      });
    }
  } catch (err) {
    console.error('❌ Fetch error:', err.message);
    return res.status(500).json({
      success: false,
      error: 'Could not reach SMS service. Please try again.'
    });
  }
});

// ─────────────────────────────────────────────
// ROUTE: POST /verify-otp
// Body: { phone: "98XXXXXXXX", otp: "123456" }
// ─────────────────────────────────────────────
app.post('/verify-otp', (req, res) => {
  const { phone, otp } = req.body;

  if (!phone || !otp) {
    return res.status(400).json({
      verified: false,
      error: 'Phone and OTP are required.'
    });
  }

  const record = otpStore[phone];

  // No OTP found
  if (!record) {
    return res.status(400).json({
      verified: false,
      error: 'No OTP found for this number. Please request a new one.'
    });
  }

  // Expired
  if (Date.now() > record.expiry) {
    delete otpStore[phone];
    return res.status(400).json({
      verified: false,
      error: 'OTP has expired. Please request a new one.'
    });
  }

  // Too many attempts
  if (record.attempts >= MAX_ATTEMPTS) {
    delete otpStore[phone];
    return res.status(400).json({
      verified: false,
      error: 'Too many failed attempts. Please request a new OTP.'
    });
  }

  // Wrong OTP
  if (record.otp !== otp.toString()) {
    record.attempts++;
    const remaining = MAX_ATTEMPTS - record.attempts;
    return res.status(400).json({
      verified: false,
      error: `Incorrect OTP. ${remaining} attempt(s) remaining.`
    });
  }

  // ✅ Correct OTP — delete and approve
  delete otpStore[phone];
  console.log(`✅ OTP verified → ${phone}`);
  return res.json({ verified: true });
});

// ── Health Check ──────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: '✅ OTP Server is running', time: new Date().toISOString() });
});

// ── Start Server ──────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 OTP Server running → http://localhost:${PORT}`);
  console.log(`   Sparrow Sender ID : ${SPARROW_SENDER}`);
  console.log(`   OTP Expiry        : ${OTP_EXPIRY_MS / 60000} minutes`);
});
