// =============================================
// server.js — OTP Backend for Shopify + Sparrow SMS
// =============================================
// Setup:
//   npm init -y
//   npm install express cors node-fetch@2
//   node server.js
//
// Render Environment Variables to set:
//   SPARROW_TOKEN         → your token from web.sparrowsms.com
//   SPARROW_SENDER        → your approved Sender ID
//   SHOPIFY_CLIENT_ID     → custom app / API client ID (for the orders-create webhook's admin token refresh)
//   SHOPIFY_CLIENT_SECRET → custom app / API client secret (also verifies the webhook's HMAC signature)
// =============================================

const express = require('express');
const cors    = require('cors');
const fetch   = require('node-fetch');
const crypto  = require('crypto');
const app     = express();

// Render sits in front of this app behind exactly one reverse-proxy hop.
// This tells Express to trust that one hop's X-Forwarded-For header when
// resolving req.ip — without it, req.ip would just be Render's internal
// proxy address, not the visitor's real IP. Setting this to `1` (rather
// than `true`) means only the outermost hop is trusted, so a client can't
// spoof their IP by sending their own fake X-Forwarded-For header.
app.set('trust proxy', 1);

app.use(cors({ origin: '*', methods: ['GET', 'POST'], allowedHeaders: ['Content-Type'] }));
app.options('*', cors());
app.use(express.json());

// ── CONFIG ────────────────────────────────────
const SPARROW_TOKEN  = process.env.SPARROW_TOKEN  || '';
const SPARROW_SENDER = process.env.SPARROW_SENDER || '';
const SPARROW_API    = 'https://api.sparrowsms.com/v2/sms/';
const OTP_EXPIRY_MS  = 5 * 60 * 1000;  // 5 minutes
const MAX_ATTEMPTS   = 5;
const PORT           = process.env.PORT || 3000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX       = 3;
const SHOP_DOMAIN    = '84d453-3.myshopify.com';
// ─────────────────────────────────────────────

if (!SPARROW_TOKEN)  console.error('❌  SPARROW_TOKEN is not set.');
if (!SPARROW_SENDER) console.error('❌  SPARROW_SENDER is not set.');
if (!process.env.SHOPIFY_CLIENT_ID)     console.error('❌  SHOPIFY_CLIENT_ID is not set.');
if (!process.env.SHOPIFY_CLIENT_SECRET) console.error('❌  SHOPIFY_CLIENT_SECRET is not set.');

// ── In-memory stores ──────────────────────────
const otpStore       = {};
const rateLimitStore = {};

// ── Cleanup every 10 minutes ──────────────────
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

// ── Helpers ───────────────────────────────────
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function isValidPhone(phone) {
  return /^[0-9]{10}$/.test(phone);
}

// Sparrow requires 977XXXXXXXXXX format
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

// Resolves an IP to city/region/country via a free, keyless lookup API.
// Never throws — on any failure it just returns blank fields, so a geo
// hiccup can't block OTP verification itself.
async function lookupGeo(ip) {
  try {
    const r = await fetch(`https://ipwho.is/${ip}`);
    const d = await r.json();
    if (d && d.success !== false) {
      return { city: d.city || '', region: d.region || '', country: d.country || '' };
    }
  } catch (e) {
    console.error('❌ Geo lookup failed:', e.message);
  }
  return { city: '', region: '', country: '' };
}

// ── Sparrow API call ──────────────────────────
async function callSparrow(to, text) {
  const params = new URLSearchParams({
    token: SPARROW_TOKEN,
    from:  SPARROW_SENDER,
    to:    to,
    text:  text
  });
  const url      = `${SPARROW_API}?${params.toString()}`;
  const masked   = url.replace(SPARROW_TOKEN, `${SPARROW_TOKEN.slice(0,6)}...${SPARROW_TOKEN.slice(-4)}`);
  console.log('📤 Sparrow request:', masked);
  const response = await fetch(url);
  const raw      = await response.text();
  console.log('📨 Sparrow response:', raw);
  try { return JSON.parse(raw); } catch(e) { return { raw }; }
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
    senderValue:  SPARROW_SENDER  || '(not set)',
    tokenPreview: SPARROW_TOKEN ? `${SPARROW_TOKEN.slice(0,6)}...${SPARROW_TOKEN.slice(-4)}` : '(not set)',
    tokenLength:  SPARROW_TOKEN.length
  });
});

// ─────────────────────────────────────────────
// ROUTE: GET /myip  — check Render outbound IP
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
// Quick test — visit in browser to verify SMS works
// ─────────────────────────────────────────────
app.get('/test-sparrow', async (req, res) => {
  const phone = req.query.phone;
  if (!phone) return res.status(400).json({ error: 'Provide ?phone=98XXXXXXXX' });
  try {
    const data = await callSparrow(formatPhone(phone), 'Test message from Allsmile OTP server.');
    res.json({ sentTo: formatPhone(phone), sparrowResult: data, senderUsed: SPARROW_SENDER });
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
      return res.status(500).json({ success: false, error: `Sparrow [${data.response_code}]: ${data.response}` });
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
app.post('/verify-otp', async (req, res) => {
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

  const clientIp = req.ip; // real visitor IP now that trust proxy is set correctly
  const geo      = await lookupGeo(clientIp);

  return res.json({
    verified: true,
    ip:       clientIp,
    city:     geo.city,
    region:   geo.region,
    country:  geo.country
  });
});

// ── Start Server ──────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 OTP Server running → http://localhost:${PORT}`);
  console.log(`   Token preview : ${SPARROW_TOKEN ? SPARROW_TOKEN.slice(0,6)+'...'+SPARROW_TOKEN.slice(-4) : 'NOT SET'}`);
  console.log(`   Token length  : ${SPARROW_TOKEN.length}`);
  console.log(`   Sender ID     : ${SPARROW_SENDER || 'NOT SET'}`);
  console.log(`   OTP Expiry    : ${OTP_EXPIRY_MS / 60000} minutes`);
});

// Always fetches a brand-new token — avoids dealing with 24hr expiry manually
async function getFreshAdminToken() {
  const response = await fetch(`https://${SHOP_DOMAIN}/admin/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.SHOPIFY_CLIENT_ID,
      client_secret: process.env.SHOPIFY_CLIENT_SECRET,
      grant_type: 'client_credentials'
    })
  });
  const data = await response.json();
  return data.access_token;
}

// ── THE ACTUAL FRAUD-CHECK HANDLER — this runs forever, keep it ──
app.post('/webhooks/orders-create',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
    const digest = crypto
      .createHmac('sha256', process.env.SHOPIFY_CLIENT_SECRET)
      .update(req.body)
      .digest('base64');

    if (digest !== hmacHeader) {
      return res.status(401).send('Invalid signature');
    }

    res.status(200).send('OK'); // acknowledge fast, Shopify expects this

    const order = JSON.parse(req.body);
    const noteAttrs = order.note_attributes || [];
    const verifiedEntry = noteAttrs.find(a => a.name === 'verified_phone');
    const verifiedPhone = verifiedEntry ? verifiedEntry.value : null;
    const orderPhone = order.phone || (order.shipping_address && order.shipping_address.phone) || null;
    const normalize = (p) => (p || '').replace(/\D/g, '').slice(-10);

    const mismatch = verifiedPhone && orderPhone && normalize(verifiedPhone) !== normalize(orderPhone);
    const missingVerification = !verifiedPhone;

    if (mismatch || missingVerification) {
      const tag = mismatch ? 'phone-mismatch' : 'no-otp-verification';
      const token = await getFreshAdminToken();
      await fetch(`https://${SHOP_DOMAIN}/admin/api/2025-01/orders/${order.id}.json`, {
        method: 'PUT',
        headers: {
          'X-Shopify-Access-Token': token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          order: {
            id: order.id,
            tags: (order.tags ? order.tags + ', ' : '') + tag
          }
        })
      });
      console.log(`Flagged order ${order.name}: ${tag}`);
    }
  }
);
// ============================================================
// META CAPI — Confirmed Purchase Webhook
// ============================================================
// Paste this into your existing server.js, below the
// /webhooks/orders-create route. It reuses SHOP_DOMAIN and
// getFreshAdminToken() that are already defined there.
//
// New env vars to add in Render:
//   META_PIXEL_ID    → your Allsmile Meta Pixel ID
//   META_ACCESS_TOKEN → Events Manager → Settings →
//                        Conversions API → Generate Access Token
//   CONFIRM_TAG       → optional, defaults to "confirmed"
//
// Note: this route reuses your existing SHOPIFY_CLIENT_SECRET for HMAC
// verification — same secret as your orders-create route, since both
// are registered under the same "Fraud check webhook" custom app.
//
// New Shopify webhook subscription (same "Fraud check webhook"
// custom app you already have):
//   Topic: Order updated (orders/updated)
//   URL:   https://server-allsmile.onrender.com/webhooks/orders-updated
// ============================================================

const CONFIRM_TAG = (process.env.CONFIRM_TAG || 'confirmed').toLowerCase();

function sha256(value) {
  return crypto.createHash('sha256').update(value.trim().toLowerCase()).digest('hex');
}

app.post('/webhooks/orders-updated',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
    const digest = crypto
      .createHmac('sha256', process.env.SHOPIFY_CLIENT_SECRET)
      .update(req.body)
      .digest('base64');

    if (digest !== hmacHeader) {
      return res.status(401).send('Invalid signature');
    }

    res.status(200).send('OK'); // ack fast, same as orders-create

    const order = JSON.parse(req.body);
    const note = (order.note || '').toLowerCase();
    const existingTags = (order.tags || '').split(',').map(t => t.trim()).filter(Boolean);

    const isConfirmed = note.includes(CONFIRM_TAG);
    const alreadySent = existingTags.includes('meta-purchase-sent');

    // Nothing to do unless the note is newly confirmed and we haven't
    // already reported this order — orders/updated fires on EVERY edit,
    // so this guard is what stops duplicate Purchase events.
    if (!isConfirmed || alreadySent) return;

    try {
      const email = order.email || order.customer?.email || '';
      const phone = order.phone || order.customer?.phone || order.shipping_address?.phone || '';

      const eventPayload = {
        data: [{
          event_name: 'Purchase',
          event_time: Math.floor(Date.now() / 1000),
          event_id: `order_${order.id}`, // lets Meta dedupe if a browser pixel ever also fires this order
          action_source: 'website',
          user_data: {
            em: email ? [sha256(email)] : undefined,
            // NOTE: strips everything but digits. Confirm your checkout phone
            // format includes the country code (9779XXXXXXXXX), or match quality
            // on this identifier drops — worth checking one real order's shape.
            ph: phone ? [sha256(phone.replace(/[^\d]/g, ''))] : undefined,
          },
          custom_data: {
            currency: order.currency,
            value: parseFloat(order.total_price),
            content_ids: (order.line_items || []).map(li => String(li.product_id)),
            content_type: 'product',
            num_items: (order.line_items || []).reduce((n, li) => n + li.quantity, 0),
          }
        }]
      };

      const capiRes = await fetch(
        `https://graph.facebook.com/v19.0/${process.env.META_PIXEL_ID}/events?access_token=${process.env.META_ACCESS_TOKEN}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(eventPayload)
        }
      );
      const capiData = await capiRes.json();

      if (capiData.error) {
        console.log(`❌ CAPI error on order ${order.id}:`, capiData.error.message);
        return;
      }

      console.log(`✅ Purchase sent to Meta → order ${order.id}, events_received: ${capiData.events_received}`);

      // Tag the order so future note edits never resend it
      const token = await getFreshAdminToken();
      const newTags = [...existingTags, 'meta-purchase-sent'].join(', ');

      // NOTE: matches your existing tag-write pattern's API version —
      // double check this against whatever version orders-create already uses.
      await fetch(`https://${SHOP_DOMAIN}/admin/api/2024-10/orders/${order.id}.json`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': token
        },
        body: JSON.stringify({ order: { id: order.id, tags: newTags } })
      });

    } catch (err) {
      console.log(`❌ Error processing confirmed order ${order.id}:`, err.message);
    }
  }
);
