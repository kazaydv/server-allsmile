// =============================================
// server.js — OTP Backend for Shopify + Sparrow SMS
// =============================================

const express = require('express');
const cors    = require('cors');
const app     = express();

// ── node-fetch v2 (CommonJS compatible) ──────
// Make sure you run: npm install node-fetch@2
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

app.use(cors({ origin: '*', methods: ['GET', 'POST'], allowedHeaders: ['Content-Type'] }));
app.options('*', cors());
app.use(express.json());

// ── CONFIG ────────────────────────────────────
const SPARROW_TOKEN  = process.env.SPARROW_TOKEN  || '';
const SPARROW_SENDER = process.env.SPARROW_SENDER || '';
const SPARROW_API    = 'https://api.sparrowsms.com/v2/sms/';
const OTP_EXPIRY_MS  = 5 * 60 * 1000;
const MAX_ATTEMPTS   = 5;
const PORT           = process.env.PORT || 3000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX       = 3;
// ─────────────────────────────────────────────

if (!SPARROW_TOKEN)  console.error('❌  SPARROW_TOKEN is not set.');
if (!SPARROW_SENDER) console.error('❌  SPARROW_SENDER is not set.');

const otpStore       = {};
const rateLimitStore = {};

setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const phone in otpStore) {
    if (now > otpStore[phone].expiry) { delete otpStore[phone]; cleaned++; }
  }
  for (const phone in rateLimitStore) {
    if (now > rateLimitStore[phone].windowStart + RATE_LIMIT_WINDOW_MS) {
      delete rateLimitStore[phone];
    }
  }
  if (cleaned > 0) console.log(`🧹 Cleaned ${cleaned} expired OTP(s)`);
}, 10 * 60 * 1000);

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function isValidPhone(phone) {
  return /^[0-9]{10}$/.test(phone);
}

function formatPhone(phone) {
  return '977' + phone.replace(/^0/, '');
}

function isRateLimited(phone) {
  const now    = Date.now();
  const record = rateLimitStore[phone];
  if (!record || now > record.windowStart + RATE_LIMIT_WINDOW_MS) {
    rateLimitStore[phone] = { count: 1, windowStart: now };
    return false;
  }
  if (record.count >= RATE_LIMIT_MAX) return true;
  record.count++;
  return false;
}

// ── Helper: call Sparrow and return full result ──
async function callSparrow(to, text) {
  const params = new URLSearchParams({
    token: SPARROW_TOKEN,
    from:  SPARROW_SENDER,
    to:    to,
    text:  text
  });
  const url = `${SPARROW_API}?${params.toString()}`;

  // Log URL with token partially masked for security
  const maskedUrl = url.replace(SPARROW_TOKEN, `${SPARROW_TOKEN.slice(0,6)}...${SPARROW_TOKEN.slice(-4)}`);
  console.log('📤 Calling Sparrow:', maskedUrl);

  const response = await fetch(url);
  const raw      = await response.text(); // get raw text first
  console.log('📨 Sparrow raw response:', raw);

  let data;
  try {
    data = JSON.parse(raw);
  } catch(e) {
    data = { parse_error: true, raw };
  }
  return data;
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
    status:       '✅ OTP Server is running',
    time:         new Date().toISOString(),
    tokenSet:     !!SPARROW_TOKEN,
    senderSet:    !!SPARROW_SENDER,
    senderValue:  SPARROW_SENDER || '(not set)',
    tokenPreview: SPARROW_TOKEN ? `${SPARROW_TOKEN.slice(0,6)}...${SPARROW_TOKEN.slice(-4)}` : '(not set)',
    tokenLength:  SPARROW_TOKEN.length
  });
});

// ─────────────────────────────────────────────
// ROUTE: GET /myip  — shows Render's outbound IP
// ─────────────────────────────────────────────
app.get('/myip', async (req, res) => {
  try {
    const r = await fetch('https://api.ipify.org?format=json');
    const d = await r.json();
    res.json({
      serverIp:     d.ip,
      tokenPreview: SPARROW_TOKEN ? `${SPARROW_TOKEN.slice(0,6)}...${SPARROW_TOKEN.slice(-4)}` : '(not set)',
      tokenLength:  SPARROW_TOKEN.length,
      senderValue:  SPARROW_SENDER || '(not set)'
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// ROUTE: GET /test-sparrow?phone=98XXXXXXXX
// Sends a real test SMS — use your own number
// e.g. https://your-server.onrender.com/test-sparrow?phone=9812345678
// ─────────────────────────────────────────────
app.get('/test-sparrow', async (req, res) => {
  const phone = req.query.phone;
  if (!phone) {
    return res.status(400).json({ error: 'Provide ?phone=98XXXXXXXX in the URL' });
  }

  const sparrowPhone = formatPhone(phone);
  console.log(`🧪 Test call → token length: ${SPARROW_TOKEN.length}, from: "${SPARROW_SENDER}", to: ${sparrowPhone}`);

  try {
    const data = await callSparrow(sparrowPhone, 'Test message from Allsmile OTP server.');
    res.json({
      sentTo:        sparrowPhone,
      sparrowResult: data,
      tokenPreview:  `${SPARROW_TOKEN.slice(0,6)}...${SPARROW_TOKEN.slice(-4)}`,
      tokenLength:   SPARROW_TOKEN.length,
      senderUsed:    SPARROW_SENDER
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// ROUTE: POST /send-otp
// Body: { phone: "98XXXXXXXX" }
// ─────────────────────────────────────────────
app.post('/send-otp', async (req, res) => {
  const { phone } = req.body;

  if (!phone || !isValidPhone(phone)) {
    return res.status(400).json({ success: false, error: 'Please enter a valid 10-digit phone number.' });
  }

  if (isRateLimited(phone)) {
    return res.status(429).json({ success: false, error: 'Too many requests. Please wait a minute.' });
  }

  if (!SPARROW_TOKEN || !SPARROW_SENDER) {
    return res.status(500).json({ success: false, error: 'SMS service is not configured.' });
  }

  const otp          = generateOtp();
  const sparrowPhone = formatPhone(phone);

  otpStore[phone] = { otp, expiry: Date.now() + OTP_EXPIRY_MS, attempts: 0 };

  const message = `Your Allsmile verification code is ${otp}. Valid for 5 minutes. Do not share this code.`;

  try {
    const data = await callSparrow(sparrowPhone, message);

    if (data.response_code === 200) {
      console.log(`✅ OTP sent → ${sparrowPhone}`);
      return res.json({ success: true });
    } else {
      console.error(`❌ Sparrow error [${data.response_code}]: ${data.response}`);
      return res.status(500).json({
        success: false,
        error: `Sparrow [${data.response_code}]: ${data.response}`
      });
    }
  } catch (err) {
    console.error('❌ Fetch error:', err.message);
    return res.status(500).json({ success: false, error: 'Could not reach SMS service.' });
  }
});

// ─────────────────────────────────────────────
// ROUTE: POST /verify-otp
// Body: { phone: "98XXXXXXXX", otp: "123456" }
// ─────────────────────────────────────────────
app.post('/verify-otp', (req, res) => {
  const { phone, otp } = req.body;

  if (!phone || !otp) {
    return res.status(400).json({ verified: false, error: 'Phone and OTP are required.' });
  }

  const record = otpStore[phone];

  if (!record) {
    return res.status(400).json({ verified: false, error: 'No OTP found. Please request a new one.' });
  }

  if (Date.now() > record.expiry) {
    delete otpStore[phone];
    return res.status(400).json({ verified: false, error: 'OTP has expired. Please request a new one.' });
  }

  if (record.attempts >= MAX_ATTEMPTS) {
    delete otpStore[phone];
    return res.status(400).json({ verified: false, error: 'Too many failed attempts. Please request a new OTP.' });
  }

  if (record.otp !== otp.toString()) {
    record.attempts++;
    const remaining = MAX_ATTEMPTS - record.attempts;
    return res.status(400).json({ verified: false, error: `Incorrect OTP. ${remaining} attempt(s) remaining.` });
  }

  delete otpStore[phone];
  console.log(`✅ OTP verified → ${phone}`);
  return res.json({ verified: true });
});

// ── Start Server ──────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 OTP Server running → http://localhost:${PORT}`);
  console.log(`   Token preview : ${SPARROW_TOKEN ? SPARROW_TOKEN.slice(0,6)+'...'+SPARROW_TOKEN.slice(-4) : 'NOT SET'}`);
  console.log(`   Token length  : ${SPARROW_TOKEN.length}`);
  console.log(`   Sender ID     : ${SPARROW_SENDER || 'NOT SET'}`);
  console.log(`   OTP Expiry    : ${OTP_EXPIRY_MS / 60000} minutes`);
});
