# Sticky Add to Cart - Shopify App

## Production Deployment Checklist

### ✅ Required Environment Variables (Set in Render)

```bash
# CRITICAL: Set these in Render Dashboard → Environment
SHOPIFY_API_SECRET=your_client_secret_from_partners_dashboard
SHOPIFY_API_KEY=5a2e451bcc74511f8be6157b743711f1
PORT=10000
NODE_ENV=production
```

### 🔐 How to Get SHOPIFY_API_SECRET

1. Go to [Shopify Partners Dashboard](https://partners.shopify.com/)
2. Navigate to **Apps** → **Sticky Add to Cart**
3. Click **App setup** or **Configuration**
4. Find **Client credentials** section
5. Click **Show** next to **Client secret**
6. Copy the value and set it in Render

### 🚀 Render Deployment Settings

**Build Command:**
```bash
npm install
```

**Start Command:**
```bash
npm start
```

### ✅ Server Features

- ✅ **HMAC Webhook Verification** - All webhooks verify `X-Shopify-Hmac-Sha256` headers
- ✅ **Stateless OAuth** - No database required for app installation
- ✅ **GDPR Compliance** - All 3 mandatory webhooks implemented
- ✅ **Production-Safe** - Proper error handling and logging
- ✅ **Extension-Only** - Minimal server for Theme App Extensions

### 📋 Endpoints

**Health Check:**
- `GET /` - Returns app status and available endpoints

**OAuth Flow:**
- `GET /auth?shop=store.myshopify.com` - Initiates OAuth
- `GET /auth/callback` - OAuth callback (HMAC verified)

**GDPR Webhooks (HMAC Verified):**
- `POST /api/webhooks/customers/data_request`
- `POST /api/webhooks/customers/redact`
- `POST /api/webhooks/shop/redact`

### 🧪 Testing Webhooks Locally

```bash
# Start server
npm start

# Test HMAC verification (will fail without valid HMAC)
curl -X POST http://localhost:3000/api/webhooks/customers/data_request \
  -H "Content-Type: application/json" \
  -H "X-Shopify-Shop-Domain: test-store.myshopify.com" \
  -d '{"shop_domain":"test-store.myshopify.com"}'
```

### ⚠️ Important Notes

1. **SHOPIFY_API_SECRET is REQUIRED** in production for HMAC verification
2. Without it, webhook verification will be skipped (dev mode only)
3. This is an **extension-only app** - no database or session storage needed
4. The server exists only to satisfy Shopify's mandatory requirements

### 🔄 After Deployment

1. Update `shopify.app.toml` with your Render URL
2. Run `npm run deploy` to push configuration to Shopify
3. Test installation on a development store
4. Submit for App Store review

---

**App Type:** Theme App Extension (Extension-Only)  
**Backend:** Minimal Node.js/Express (Stateless)  
**Database:** None (Not Required)  
**Purpose:** GDPR Compliance & OAuth Only
