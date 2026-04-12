// =============================================
// server.js — OTP Backend for Shopify + Sparrow SMS
// =============================================
// Setup:
//   npm init -y
//   npm install express cors node-fetch
//   node server.js
//
// On Render — set these Environment Variables:
//   SPARROW_TOKEN   → your token from web.sparrowsms.com
//   SPARROW_SENDER  → your approved Sender ID (e.g. Allsmile)
// =============================================

const express = require('express');
const cors    = require('cors');
const app     = express();

// ── node-fetch fallback (works on Node 16 and Node 18+) ──
const fetcher = (...args) => {
  if (typeof fetch !== 'undefined') {
    return fetch(...args);               // Node 18+ built-in
  }
  return require('node-fetch')(...args); // Node 16 fallback
};

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));
app.options('*', cors());
app.use(express.json());

// ── CONFIG ────────────────────────────────────
const SPARROW_TOKEN  = process.env.SPARROW_TOKEN  || '';
const SPARROW_SENDER = process.env.SPARROW_SENDER || 'Allsmile';
const SPARROW_API    = 'https://api.sparrowsms.com/v2/sms/';
const OTP_EXPIRY_MS  = 5 * 60 * 1000;
const MAX_ATTEMPTS   = 5;
const PORT           = process.env.PORT || 3000;

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX       = 3;
// ─────────────────────────────────────────────

if (!SPARROW_TOKEN) {
  console.error('❌  SPARROW_TOKEN environment variable is not set. SMS will not work.');
}

// ── In-memory stores ──────────────────────────
const otpStore       = {};
const rateLimitStore = {};

// ── Cleanup expired OTPs every 10 minutes ─────
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const phone in otpStore) {
    if (now > otpStore[phone].expiry) {
      delete otpStore[phone];
      cleaned++;
    }
  }
  for (const phone in rateLimitStore) {
    if (now > rateLimitStore[phone].windowStart + RATE_LIMIT_WINDOW_MS) {
      delete rateLimitStore[phone];
    }
  }
  if (cleaned > 0) console.log(`🧹 Cleaned ${cleaned} expired OTP(s)`);
}, 10 * 60 * 1000);

// ── Helper: Generate 6-digit OTP ─────────────
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ── Helper: Validate Nepal phone number ──────
function isValidPhone(phone) {
  return /^[0-9]{10}$/.test(phone);
}

// ── Helper: Format phone for Sparrow ─────────
// Sparrow requires 977XXXXXXXXXX format
function formatPhone(phone) {
  const digits = phone.replace(/^0/, ''); // strip leading 0 if present
  return '977' + digits;
}

// ── Helper: Rate limit check ──────────────────
function isRateLimited(phone) {
  const now    = Date.now();
  const record = rateLimitStore[phone];

  if (!record || now > record.windowStart + RATE_LIMIT_WINDOW_MS) {
    rateLimitStore[phone] = { count: 1, windowStart: now };
    return false;
  }

  if (record.count >= RATE_LIMIT_MAX) {
    return true;
  }

  record.count++;
  return false;
}

// ─────────────────────────────────────────────
// ROUTE: GET /health
// ─────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// ─────────────────────────────────────────────
// ROUTE: GET /
// ─────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status:   '✅ OTP Server is running',
    time:     new Date().toISOString(),
    smsReady: !!SPARROW_TOKEN
  });
});

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

  if (isRateLimited(phone)) {
    return res.status(429).json({
      success: false,
      error: 'Too many requests. Please wait a minute before requesting a new OTP.'
    });
  }

  if (!SPARROW_TOKEN) {
    return res.status(500).json({
      success: false,
      error: 'SMS service is not configured. Please contact support.'
    });
  }

  const otp          = generateOtp();
  const sparrowPhone = formatPhone(phone); // e.g. 9812345678 → 9779812345678

  otpStore[phone] = {
    otp,
    expiry:   Date.now() + OTP_EXPIRY_MS,
    attempts: 0
  };

  const message = `Your Allsmile verification code is ${otp}. Valid for 5 minutes. Do not share this code.`;

  console.log(`📤 Sending OTP to ${sparrowPhone} via Sparrow...`);

  try {
    // ✅ POST with JSON body — correct method for Sparrow v2
    const response = await fetcher(SPARROW_API, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        token: SPARROW_TOKEN,
        to:    sparrowPhone,
        text:  message
      })
    });

    const data = await response.json();
    console.log('📨 Sparrow full response:', JSON.stringify(data));

    if (data.response_code === 200) {
      console.log(`✅ OTP sent → ${sparrowPhone}`);
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

  if (!record) {
    return res.status(400).json({
      verified: false,
      error: 'No OTP found for this number. Please request a new one.'
    });
  }

  if (Date.now() > record.expiry) {
    delete otpStore[phone];
    return res.status(400).json({
      verified: false,
      error: 'OTP has expired. Please request a new one.'
    });
  }

  if (record.attempts >= MAX_ATTEMPTS) {
    delete otpStore[phone];
    return res.status(400).json({
      verified: false,
      error: 'Too many failed attempts. Please request a new OTP.'
    });
  }

  if (record.otp !== otp.toString()) {
    record.attempts++;
    const remaining = MAX_ATTEMPTS - record.attempts;
    return res.status(400).json({
      verified: false,
      error: `Incorrect OTP. ${remaining} attempt(s) remaining.`
    });
  }

  // ✅ Correct — clean up and approve
  delete otpStore[phone];
  console.log(`✅ OTP verified → ${phone}`);
  return res.json({ verified: true });
});

// ── Start Server ──────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 OTP Server running → http://localhost:${PORT}`);
  console.log(`   Sparrow Sender ID : ${SPARROW_SENDER}`);
  console.log(`   OTP Expiry        : ${OTP_EXPIRY_MS / 60000} minutes`);
  console.log(`   SMS Ready         : ${!!SPARROW_TOKEN}`);
});
