/**
 * Chrome Profile Lock - Backend API Server
 *
 * Implements:
 * - GET  /health, /api/health (service health probe)
 * - POST /test-email, /api/test-email (verified email test via Resend Node SDK)
 * - POST /api/request-recovery, /request-recovery (generates 6-digit OTP & sends via Resend)
 * - POST /api/verify-recovery-otp, /verify-recovery-otp (verifies OTP & issues cryptographic token)
 * - POST /api/complete-recovery, /complete-recovery (finalizes recovery & consumes token)
 * - POST /api/send-email-verification (Options page email verification dispatch)
 * - POST /api/confirm-email-verification (Options page verification confirmation)
 * - POST /api/security-alert, /security-alert (5-failed-attempts security warning alert)
 *
 * Strict Security Rules:
 * - Zero plaintext password or token logging
 * - Timing-safe constant-time string comparisons (crypto.timingSafeEqual)
 * - HMAC-SHA256 signed single-use recovery tokens
 * - Expiration and rate-limiting on all OTP requests
 * - Never returns internal secrets or stack traces
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Resend } = require('resend');

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const isProduction = process.env.NODE_ENV === 'production';
const allowedOriginConfig = process.env.ALLOWED_ORIGIN || 'chrome-extension://*';

// Cryptographic secrets & Email Configuration
const recoverySecret = process.env.RECOVERY_SIGNING_SECRET || 'cpl-fallback-signing-secret-key-32b';
const gmailUser = (process.env.GMAIL_USER || 'admin.email.dev@gmail.com').trim();
const gmailPass = (process.env.GMAIL_APP_PASSWORD || '').trim().replace(/\s+/g, '');
const resendApiKey = (process.env.EMAIL_API_KEY || '').trim();

let gmailTransporter = null;
if (gmailPass) {
  gmailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: gmailUser,
      pass: gmailPass
    }
  });
  console.log(`[CPL Backend] Gmail SMTP service initialized for: ${gmailUser}`);
}

let resendClient = null;
if (resendApiKey) {
  resendClient = new Resend(resendApiKey);
}

if (!gmailTransporter && !resendClient) {
  console.warn('[CPL Backend Warning] Neither GMAIL_APP_PASSWORD nor EMAIL_API_KEY is configured in backend/.env.');
}

// -----------------------------------------------------------------------------
// In-Memory Storage & Rate Limiting (Single-instance safe)
// -----------------------------------------------------------------------------
// Maps requestId -> { requestId, email, otpHash, attempts, expiresAt, verified, recoveryToken, type }
const otpStore = new Map();

// Maps email -> { count, resetAt }
const rateLimitStore = new Map();

function checkRateLimit(email, maxRequests = 5, windowMinutes = 15) {
  const key = email.toLowerCase().trim();
  const now = Date.now();
  const entry = rateLimitStore.get(key);

  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + windowMinutes * 60 * 1000 });
    return true;
  }

  if (entry.count >= maxRequests) {
    return false;
  }

  entry.count++;
  return true;
}

// Cleanup expired OTPs and rate limit entries every 2 minutes
const cleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [reqId, data] of otpStore.entries()) {
    if (now > data.expiresAt) {
      otpStore.delete(reqId);
    }
  }
  for (const [email, limit] of rateLimitStore.entries()) {
    if (now > limit.resetAt) {
      rateLimitStore.delete(email);
    }
  }
}, 2 * 60 * 1000);
if (cleanupInterval.unref) {
  cleanupInterval.unref();
}

// -----------------------------------------------------------------------------
// Middleware Configuration
// -----------------------------------------------------------------------------

app.use(cors({
  origin: (origin, callback) => {
    // Non-browser requests (curl, server-to-server)
    if (!origin) return callback(null, true);

    // Chrome extensions
    if (origin.startsWith('chrome-extension://')) {
      return callback(null, true);
    }

    // Localhost development
    if (!isProduction && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
      return callback(null, true);
    }

    const allowedList = allowedOriginConfig.split(',').map(o => o.trim());
    if (allowedList.includes('*') && !isProduction) {
      return callback(null, true);
    }
    if (allowedList.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error('Blocked by CORS policy'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50kb' }));

// -----------------------------------------------------------------------------
// Helper Utilities
// -----------------------------------------------------------------------------

function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function getSenderInfo() {
  const fromEmail = process.env.EMAIL_FROM || 'admin.email.dev@email.com';
  const fromName = process.env.EMAIL_FROM_NAME || 'Chrome Profile Lock';
  return `${fromName} <${fromEmail}>`;
}

function hashValue(val) {
  return crypto.createHash('sha256').update(val).digest('hex');
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// -----------------------------------------------------------------------------
// Unified Email Dispatcher (Gmail SMTP Priority + Resend API Fallback)
// -----------------------------------------------------------------------------

async function sendEmailNotification({ to, subject, text, html }) {
  const recipientList = Array.isArray(to) ? to.map(e => e.trim().toLowerCase()) : [to.trim().toLowerCase()];
  const fromName = process.env.EMAIL_FROM_NAME || 'Chrome Profile Lock';

  // 1. Primary Provider: Personal Gmail SMTP
  if (gmailTransporter) {
    try {
      const info = await gmailTransporter.sendMail({
        from: `"${fromName}" <${gmailUser}>`,
        to: recipientList.join(', '),
        subject: subject,
        text: text,
        html: html || text
      });
      console.log(`[CPL Backend] Email dispatched via Gmail SMTP from ${gmailUser} to: ${recipientList.join(', ')} (ID: ${info.messageId})`);
      return { success: true, provider: 'gmail', messageId: info.messageId };
    } catch (err) {
      console.error('[CPL Backend Gmail SMTP Error]', err.message);
      if (!resendClient) {
        return { success: false, error: `Gmail error: ${err.message}` };
      }
      console.log('[CPL Backend] Falling back to Resend provider...');
    }
  }

  // 2. Secondary Provider: Resend API
  if (resendClient) {
    try {
      const { data, error } = await resendClient.emails.send({
        from: getSenderInfo(),
        to: recipientList,
        subject: subject,
        text: text,
        html: html
      });
      if (error) {
        console.error('[CPL Backend Resend Error]', error.message);
        return { success: false, error: error.message };
      }
      console.log(`[CPL Backend] Email dispatched via Resend API to: ${recipientList.join(', ')}`);
      return { success: true, provider: 'resend', data };
    } catch (err) {
      console.error('[CPL Backend Resend Error]', err.message);
      return { success: false, error: err.message };
    }
  }

  return {
    success: false,
    error: 'No email service is configured. Please provide GMAIL_APP_PASSWORD in backend/.env.'
  };
}

// -----------------------------------------------------------------------------
// Health Check Routes
// -----------------------------------------------------------------------------

const healthHandler = (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'chrome-profile-lock-api'
  });
};

app.get('/health', healthHandler);
app.get('/api/health', healthHandler);
app.get('/', healthHandler);

// -----------------------------------------------------------------------------
// Route: POST /test-email & /api/test-email
// -----------------------------------------------------------------------------

const testEmailHandler = async (req, res) => {
  try {
    const { to } = req.body || {};

    if (!to || !isValidEmail(to)) {
      return res.status(400).json({
        success: false,
        error: 'A valid recipient email address is required.'
      });
    }

    const result = await sendEmailNotification({
      to: to.trim(),
      subject: 'Chrome Profile Lock Test',
      text: 'This is a test email from Chrome Profile Lock.'
    });

    if (!result.success) {
      return res.status(502).json({
        success: false,
        error: result.error || 'Failed to send test email.'
      });
    }

    return res.status(200).json({ success: true, provider: result.provider });
  } catch (err) {
    console.error('[CPL Backend Internal Error]', err.message || 'Unexpected error');
    return res.status(500).json({
      success: false,
      error: 'An internal error occurred while dispatching the test email.'
    });
  }
};

app.post('/test-email', testEmailHandler);
app.post('/api/test-email', testEmailHandler);

// -----------------------------------------------------------------------------
// Route: POST /api/request-recovery & /request-recovery (OTP Dispatch)
// -----------------------------------------------------------------------------

const requestRecoveryHandler = async (req, res) => {
  try {
    const { email } = req.body || {};

    if (!email || !isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        error: 'A valid email address is required.'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Check rate limit (max 5 requests per 15 minutes)
    if (!checkRateLimit(normalizedEmail, 5, 15)) {
      return res.status(429).json({
        success: false,
        error: 'Too many recovery requests. Please wait 15 minutes before trying again.'
      });
    }

    if (!resendClient) {
      console.error('[CPL Backend] Resend client is not initialized.');
      return res.status(500).json({
        success: false,
        error: 'Email service is not configured. Please verify your backend environment.'
      });
    }

    // Generate cryptographically secure 6-digit numeric OTP
    const otp = crypto.randomInt(100000, 1000000).toString();
    const otpHash = hashValue(otp);
    const requestId = crypto.randomUUID();
    const expiresIn = 300; // 5 minutes (seconds)
    const expiresAt = Date.now() + expiresIn * 1000;

    // Save in OTP store
    otpStore.set(requestId, {
      requestId,
      email: normalizedEmail,
      otpHash,
      attempts: 0,
      expiresAt,
      verified: false,
      type: 'recovery'
    });

    // Send email via Resend SDK
    const emailHtml = `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px 24px; background-color: #12151c; color: #e8eaed; border-radius: 12px; border: 1px solid #232a38;">
        <div style="text-align: center; margin-bottom: 24px;">
          <div style="display: inline-block; width: 48px; height: 48px; line-height: 48px; font-size: 24px; background-color: #1a2f4c; border-radius: 50%; color: #8ab4f8; margin-bottom: 12px;">🔒</div>
          <h1 style="font-size: 20px; font-weight: 600; margin: 0; color: #ffffff;">Chrome Profile Lock</h1>
          <p style="font-size: 14px; color: #9aa0a6; margin: 6px 0 0 0;">Authentication Reset Request</p>
        </div>
        <div style="background-color: #1a1e28; border: 1px solid #2b3345; border-radius: 8px; padding: 20px; text-align: center; margin-bottom: 24px;">
          <p style="font-size: 14px; color: #9aa0a6; margin: 0 0 12px 0;">Use the following 6-digit verification code to reset your profile credentials:</p>
          <div style="font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #8ab4f8; font-family: monospace; padding: 12px; background-color: #12151c; border-radius: 6px; border: 1px dashed #3a455c;">
            ${otp}
          </div>
          <p style="font-size: 12px; color: #80868b; margin: 12px 0 0 0;">This code expires in <strong>5 minutes</strong>.</p>
        </div>
        <p style="font-size: 12px; color: #80868b; line-height: 1.5; margin: 0; text-align: center;">
          If you did not request this verification code, someone may be attempting to access your Chrome profile. Please ensure your device is physically secure.
        </p>
      </div>
    `;

    const sendResult = await sendEmailNotification({
      to: normalizedEmail,
      subject: 'Chrome Profile Lock - Verification Code',
      text: `Your Chrome Profile Lock verification code is: ${otp}\n\nThis code expires in 5 minutes. If you did not request this code, please secure your browser.`,
      html: emailHtml
    });

    if (!sendResult.success) {
      otpStore.delete(requestId);
      return res.status(502).json({
        success: false,
        error: sendResult.error || 'Failed to dispatch verification code via email provider.'
      });
    }

    console.log(`[CPL Backend] Recovery OTP dispatched successfully for requestId: ${requestId} via ${sendResult.provider}`);

    return res.status(200).json({
      success: true,
      requestId,
      expiresIn,
      provider: sendResult.provider
    });

  } catch (err) {
    console.error('[CPL Backend Recovery Error]', err.message || 'Unexpected error');
    return res.status(500).json({
      success: false,
      error: 'An internal error occurred while requesting recovery.'
    });
  }
};

app.post('/api/request-recovery', requestRecoveryHandler);
app.post('/request-recovery', requestRecoveryHandler);

// -----------------------------------------------------------------------------
// Route: POST /api/verify-recovery-otp & /verify-recovery-otp
// -----------------------------------------------------------------------------

const verifyRecoveryOtpHandler = async (req, res) => {
  try {
    const { requestId, otp } = req.body || {};

    if (!requestId || !otp) {
      return res.status(400).json({
        success: false,
        error: 'Request ID and verification code are required.'
      });
    }

    const record = otpStore.get(requestId);
    if (!record) {
      return res.status(404).json({
        success: false,
        error: 'Verification session not found or expired. Please request a new code.'
      });
    }

    if (Date.now() > record.expiresAt) {
      otpStore.delete(requestId);
      return res.status(410).json({
        success: false,
        error: 'Verification code has expired. Please request a new code.'
      });
    }

    record.attempts++;
    if (record.attempts > 5) {
      otpStore.delete(requestId);
      return res.status(429).json({
        success: false,
        error: 'Too many incorrect attempts. This verification session has been terminated.'
      });
    }

    const candidateHash = hashValue(otp.trim());
    if (!safeEqual(candidateHash, record.otpHash)) {
      return res.status(401).json({
        success: false,
        error: 'Incorrect verification code. Please try again.'
      });
    }

    // OTP is valid! Issue HMAC-SHA256 recovery token
    record.verified = true;
    const tokenPayload = `${record.requestId}:${record.email}:${Date.now()}`;
    const hmac = crypto.createHmac('sha256', recoverySecret).update(tokenPayload).digest('hex');
    const recoveryToken = `${Buffer.from(tokenPayload).toString('base64url')}.${hmac}`;
    record.recoveryToken = recoveryToken;

    console.log(`[CPL Backend] Recovery OTP verified for requestId: ${requestId}`);

    return res.status(200).json({
      success: true,
      recoveryToken
    });

  } catch (err) {
    console.error('[CPL Backend OTP Verify Error]', err.message || 'Unexpected error');
    return res.status(500).json({
      success: false,
      error: 'An internal error occurred while verifying the code.'
    });
  }
};

app.post('/api/verify-recovery-otp', verifyRecoveryOtpHandler);
app.post('/verify-recovery-otp', verifyRecoveryOtpHandler);

// -----------------------------------------------------------------------------
// Route: POST /api/complete-recovery & /complete-recovery
// -----------------------------------------------------------------------------

const completeRecoveryHandler = async (req, res) => {
  try {
    const { requestId, recoveryToken } = req.body || {};

    if (!requestId || !recoveryToken) {
      return res.status(400).json({
        success: false,
        error: 'Request ID and recovery token are required.'
      });
    }

    const record = otpStore.get(requestId);
    if (!record || !record.verified || !record.recoveryToken) {
      return res.status(403).json({
        success: false,
        error: 'Recovery session is invalid or has already been used.'
      });
    }

    if (Date.now() > record.expiresAt) {
      otpStore.delete(requestId);
      return res.status(410).json({
        success: false,
        error: 'Recovery token has expired. Please restart recovery.'
      });
    }

    // Validate token signature
    if (!safeEqual(recoveryToken, record.recoveryToken)) {
      return res.status(403).json({
        success: false,
        error: 'Invalid recovery token signature.'
      });
    }

    // Consume single-use token immediately
    otpStore.delete(requestId);
    console.log(`[CPL Backend] Recovery finalized and token consumed for requestId: ${requestId}`);

    return res.status(200).json({
      success: true
    });

  } catch (err) {
    console.error('[CPL Backend Complete Recovery Error]', err.message || 'Unexpected error');
    return res.status(500).json({
      success: false,
      error: 'An internal error occurred while completing recovery.'
    });
  }
};

app.post('/api/complete-recovery', completeRecoveryHandler);
app.post('/complete-recovery', completeRecoveryHandler);

// -----------------------------------------------------------------------------
// Options Page Verification Routes: send-email-verification & confirm-email-verification
// -----------------------------------------------------------------------------

app.post('/api/send-email-verification', async (req, res) => {
  try {
    const { email, type } = req.body || {};
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ success: false, error: 'A valid email is required.' });
    }

    if (!checkRateLimit(email, 5, 15)) {
      return res.status(429).json({ success: false, error: 'Too many verification requests. Please wait.' });
    }

    if (!resendClient) {
      return res.status(500).json({ success: false, error: 'Email service is not configured.' });
    }

    const otp = crypto.randomInt(100000, 1000000).toString();
    const requestId = crypto.randomUUID();
    const expiresIn = 300;

    otpStore.set(requestId, {
      requestId,
      email: email.trim().toLowerCase(),
      otpHash: hashValue(otp),
      attempts: 0,
      expiresAt: Date.now() + expiresIn * 1000,
      verified: false,
      type: type || 'email-verification'
    });

    const sendResult = await sendEmailNotification({
      to: email.trim(),
      subject: 'Chrome Profile Lock - Verification Code',
      text: `Your Chrome Profile Lock email verification code is: ${otp}\n\nThis code expires in 5 minutes.`
    });

    if (!sendResult.success) {
      otpStore.delete(requestId);
      return res.status(502).json({ success: false, error: sendResult.error || 'Failed to send email.' });
    }

    return res.status(200).json({ success: true, requestId, expiresIn, provider: sendResult.provider });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/confirm-email-verification', async (req, res) => {
  try {
    const { requestId, code } = req.body || {};
    if (!requestId || !code) {
      return res.status(400).json({ success: false, error: 'Request ID and verification code are required.' });
    }

    const record = otpStore.get(requestId);
    if (!record || Date.now() > record.expiresAt) {
      return res.status(404).json({ success: false, error: 'Verification session expired or invalid.' });
    }

    if (!safeEqual(hashValue(code.trim()), record.otpHash)) {
      return res.status(401).json({ success: false, error: 'Incorrect verification code.' });
    }

    otpStore.delete(requestId);
    return res.status(200).json({ success: true });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

// -----------------------------------------------------------------------------
// Route: POST /api/security-alert & /security-alert (5 Failed Attempts Notification)
// -----------------------------------------------------------------------------

const securityAlertHandler = async (req, res) => {
  try {
    const { email, profileName } = req.body || {};

    if (!email || !isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        error: 'A valid alert recipient email address is required.'
      });
    }

    if (!resendClient) {
      return res.status(500).json({
        success: false,
        error: 'Email service is not configured.'
      });
    }

    const profile = profileName || 'Your Profile';
    const timestamp = new Date().toUTCString();

    const alertHtml = `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px 24px; background-color: #12151c; color: #e8eaed; border-radius: 12px; border: 1px solid #3c1e1e;">
        <div style="text-align: center; margin-bottom: 24px;">
          <div style="display: inline-block; width: 52px; height: 52px; line-height: 52px; font-size: 26px; background-color: #3b1818; border-radius: 50%; color: #f28b82; margin-bottom: 12px;">⚠️</div>
          <h1 style="font-size: 20px; font-weight: 600; margin: 0; color: #f28b82;">Security Warning: Multiple Failed Unlock Attempts</h1>
          <p style="font-size: 14px; color: #9aa0a6; margin: 6px 0 0 0;">Chrome Profile Lock Intrusion Detection</p>
        </div>
        <div style="background-color: #1a1e28; border: 1px solid #2b3345; border-radius: 8px; padding: 18px; margin-bottom: 20px;">
          <p style="font-size: 14px; color: #e8eaed; margin: 0 0 8px 0;"><strong>Profile Protected:</strong> ${profile}</p>
          <p style="font-size: 14px; color: #e8eaed; margin: 0 0 8px 0;"><strong>Incident:</strong> 5 consecutive failed unlock attempts detected</p>
          <p style="font-size: 14px; color: #e8eaed; margin: 0;"><strong>Time (UTC):</strong> ${timestamp}</p>
        </div>
        <p style="font-size: 13px; color: #9aa0a6; line-height: 1.5; margin: 0 0 16px 0;">
          The profile lock screen engaged rate-limiting lockout protection. If this was not you, someone may be trying to guess your credentials on this computer.
        </p>
        <p style="font-size: 12px; color: #80868b; line-height: 1.4; margin: 0; border-top: 1px solid #232a38; padding-top: 14px;">
          Automated security dispatch by Chrome Profile Lock.
        </p>
      </div>
    `;

    const sendResult = await sendEmailNotification({
      to: email.trim().toLowerCase(),
      subject: `Security Alert: Multiple Failed Unlock Attempts on "${profile}"`,
      text: `Security Alert: 5 consecutive failed unlock attempts were detected on your Chrome Profile "${profile}" at ${timestamp}. If this was not you, someone may be attempting to access your profile.`,
      html: alertHtml
    });

    if (!sendResult.success) {
      return res.status(502).json({ success: false, error: sendResult.error });
    }

    console.log(`[CPL Backend] Security alert email successfully sent to ${email} via ${sendResult.provider}`);
    return res.status(200).json({ success: true, provider: sendResult.provider });

  } catch (err) {
    console.error('[CPL Backend Alert Error]', err.message);
    return res.status(500).json({ success: false, error: 'Internal server error.' });
  }
};

app.post('/api/security-alert', securityAlertHandler);
app.post('/security-alert', securityAlertHandler);

// -----------------------------------------------------------------------------
// 404 Handler & Global Error Handler
// -----------------------------------------------------------------------------

app.use((req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Endpoint not found.'
  });
});

app.use((err, req, res, next) => {
  console.error('[CPL Backend Unhandled Error]', err.message || 'Internal server error');
  res.status(500).json({
    status: 'error',
    message: 'Internal server error.'
  });
});

// -----------------------------------------------------------------------------
// Server Start
// -----------------------------------------------------------------------------

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[CPL Backend] Server listening on http://localhost:${PORT}`);
    console.log(`[CPL Backend] Health check: http://localhost:${PORT}/health`);
  });
}

module.exports = app;
