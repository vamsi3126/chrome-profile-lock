# Chrome Profile Lock - Backend API

Express and Node.js security backend for the **Chrome Profile Lock** extension, integrating Resend for email dispatching.

---

## 📋 Features

- **Health Probe**: `GET /health` returns service status.
- **Test Email**: `POST /test-email` dispatches test emails using the official Resend Node SDK.
- **Security-First Architecture**:
  - Zero plaintext secrets or API keys exposed through endpoints or logs.
  - Granular CORS control for Chrome extensions.
  - Safe payload limits and strict input validation.

---

## 🚀 Getting Started

### 1. Install Dependencies
Ensure Node.js (v18+) is installed, then run:
```bash
cd backend
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Open `.env` and set your configuration:
```env
PORT=3000
EMAIL_API_KEY=your_resend_api_key_here
EMAIL_FROM=admin.email.dev@email.com
EMAIL_FROM_NAME=Chrome Profile Lock
OTP_ENCRYPTION_KEY=your_generated_random_32_byte_hex_key
RECOVERY_SIGNING_SECRET=your_generated_random_32_byte_hex_key
ALLOWED_ORIGIN=chrome-extension://*
```

> **Note**: Generate strong 32-byte cryptographic hex keys with:
> ```bash
> node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
> ```

---

### 3. Start the Server

**Production / Standard Mode:**
```bash
npm start
```
Starts the server with `node server.js` on `http://localhost:3000`.

**Development Mode (Live Reload):**
```bash
npm run dev
```
Starts the server with `nodemon server.js` for automatic reloads on code changes.

---

## 🧪 Testing the API

### 4. Test `GET /health`
Verify that the service is running and healthy:

**cURL:**
```bash
curl http://localhost:3000/health
```

**PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:3000/health" -Method Get
```

**Expected Response (HTTP 200):**
```json
{
  "status": "ok",
  "service": "chrome-profile-lock-api"
}
```

---

### 5. Test `POST /test-email`
Send a test email through Resend:

**cURL:**
```bash
curl -X POST http://localhost:3000/test-email \
  -H "Content-Type: application/json" \
  -d '{"to": "recipient@example.com"}'
```

**PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:3000/test-email" `
  -Method Post `
  -Headers @{ "Content-Type" = "application/json" } `
  -Body '{"to": "recipient@example.com"}'
```

**Expected Success Response (HTTP 200):**
```json
{
  "success": true
}
```

**Error Handling Example (HTTP 502 / 400):**
```json
{
  "success": false,
  "error": "The domain is not verified. Please, add and verify your domain on https://resend.com/domains"
}
```

---

## 🔒 Security Rules

1. **Never Commit Secrets**: The `.env` file is excluded in `.gitignore` and must never be committed to source control.
2. **Never Log Credentials**: Passwords, PINs, OTP codes, recovery tokens, and Resend API keys are strictly forbidden from stdout / stderr logs.
3. **Never Expose Configuration**: The `/health` and error handlers never reveal environment variables or internal call stacks.
4. **Origin Restrictions**: In production, `ALLOWED_ORIGIN` must be set to your specific Chrome Extension ID (e.g. `chrome-extension://abcdefghijklmnop`).

---

## 🌐 Production Deployment Preparation

1. **Deploy to a Cloud Platform**:
   - Compatible with Vercel, Render, Railway, AWS ECS/Lambda, or DigitalOcean App Platform.
2. **Set Cloud Environment Variables**:
   - Set `EMAIL_API_KEY`, `EMAIL_FROM`, `EMAIL_FROM_NAME`, `OTP_ENCRYPTION_KEY`, and `RECOVERY_SIGNING_SECRET` in your hosting provider's dashboard.
   - Set `NODE_ENV=production`.
3. **Verify Domain in Resend**:
   - Navigate to [Resend Domains](https://resend.com/domains).
   - Add your sending domain (e.g. `yourdomain.com`).
   - Add the required DKIM and SPF DNS records to your DNS provider.
   - Update `EMAIL_FROM` to use your verified domain address.
4. **Configure Chrome Extension**:
   - In `options.html` of Chrome Profile Lock, configure the **Backend Security API URL** to point to your deployed production HTTPS domain.
