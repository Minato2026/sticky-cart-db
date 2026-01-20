// ================= SHOPIFY NODE ADAPTER =================
require('@shopify/shopify-api/adapters/node');

// ================= IMPORTS =================
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fetch = (...args) =>
  import('node-fetch').then(({ default: fetch }) => fetch(...args));

// ================= APP SETUP =================
const app = express();
const PORT = process.env.PORT || 3000;

// ================= ENV VARIABLES =================
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET;
const HOST = process.env.HOST;
const SCOPES = process.env.SCOPES || 'write_themes';
const API_VERSION = '2024-01';

if (!SHOPIFY_API_KEY || !SHOPIFY_API_SECRET || !HOST) {
  console.error('❌ Missing required environment variables');
  process.exit(1);
}

// ================= UNIFIED WEBHOOK ENDPOINT =================
// CRITICAL: MUST be before body parsers
// This endpoint handles ALL webhooks including GDPR compliance
app.post(
  '/api/webhooks',
  express.text({ type: 'application/json' }),
  (req, res) => {
    const hmac = req.headers['x-shopify-hmac-sha256'];
    const topic = req.headers['x-shopify-topic'];
    const shop = req.headers['x-shopify-shop-domain'];

    // Validate HMAC
    if (!hmac) {
      console.error('[WEBHOOK] Missing HMAC header');
      return res.status(401).send('Unauthorized');
    }

    // HMAC verification using raw body
    const generatedHmac = crypto
      .createHmac('sha256', SHOPIFY_API_SECRET)
      .update(req.body)
      .digest('base64');

    if (generatedHmac !== hmac) {
      console.error('[WEBHOOK] HMAC verification failed');
      console.error('[WEBHOOK] Expected:', hmac);
      console.error('[WEBHOOK] Generated:', generatedHmac);
      return res.status(401).send('Unauthorized');
    }

    // HMAC valid - log success
    console.log(`[WEBHOOK] ✅ ${topic} from ${shop}`);
    console.log('[HMAC] ✅ Valid webhook signature');

    // Handle GDPR compliance webhooks - IMMEDIATE RESPONSE
    if (topic === 'customers/data_request' ||
      topic === 'customers/redact' ||
      topic === 'shop/redact') {
      console.log(`[PRIVACY] ✅ ${topic}`);
      return res.status(200).send('OK');
    }

    // Handle app/uninstalled
    if (topic === 'app/uninstalled') {
      console.log(`[WEBHOOK] App uninstalled from ${shop}`);
      // Optional: Clean up data here
    }

    // Always return 200 OK
    return res.status(200).send('OK');
  }
);

// ================= BODY PARSERS =================
// CRITICAL: MUST come AFTER webhook route
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ================= SESSION TOKEN VERIFICATION =================
// Middleware to verify Shopify session tokens (JWT)
function verifySessionToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('[SESSION TOKEN] Missing or invalid Authorization header');
    return res.status(401).json({ error: 'Unauthorized - No session token' });
  }

  const token = authHeader.substring(7); // Remove 'Bearer ' prefix

  try {
    // Verify JWT using Shopify API Secret
    const decoded = jwt.verify(token, SHOPIFY_API_SECRET, {
      algorithms: ['HS256']
    });

    // Extract shop domain from token
    const shop = decoded.dest.replace('https://', '');

    // Attach shop to request for use in route handlers
    req.shop = shop;
    req.sessionToken = decoded;

    console.log(`[SESSION TOKEN] ✅ Verified for shop: ${shop}`);
    next();
  } catch (error) {
    console.error('[SESSION TOKEN] ❌ Verification failed:', error.message);
    return res.status(401).json({ error: 'Invalid session token' });
  }
}

// ================= OAUTH HMAC VERIFY =================
function verifyOAuthHmac(query) {
  const { hmac, ...params } = query;
  if (!hmac) return false;

  const message = Object.keys(params)
    .sort()
    .map(key => `${key}=${params[key]}`)
    .join('&');

  const generated = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(message)
    .digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(generated, 'utf8'),
    Buffer.from(hmac, 'utf8')
  );
}

// ================= REGISTER WEBHOOK =================
async function registerWebhooks(shop, accessToken) {
  // Register app/uninstalled via REST API
  try {
    const response = await fetch(
      `https://${shop}/admin/api/${API_VERSION}/webhooks.json`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': accessToken
        },
        body: JSON.stringify({
          webhook: {
            topic: 'app/uninstalled',
            address: `${HOST}/api/webhooks`,
            format: 'json'
          }
        })
      }
    );

    if (response.ok) {
      console.log('[WEBHOOK] ✅ Registered app/uninstalled');
    } else {
      const error = await response.text();
      console.error('[WEBHOOK] ❌ Registration failed:', error);
    }
  } catch (error) {
    console.error('[WEBHOOK] ❌ Error:', error.message);
  }
}

// ================= PROTECTED API ENDPOINT =================
// Example endpoint that requires session token authentication
app.get('/api/data', verifySessionToken, (req, res) => {
  // req.shop is available from the verified session token
  res.json({
    success: true,
    shop: req.shop,
    message: 'Session token verified successfully!',
    timestamp: new Date().toISOString()
  });
});

// ================= HEALTH CHECK =================
app.get('/', (_, res) => {
  res.status(200).send('OK');
});

// ================= AUTH =================
app.get('/auth', (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).send('Missing shop parameter');

  const redirectUri = `${HOST}/auth/callback`;

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_API_KEY}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}`;

  return res.redirect(installUrl);
});

// ================= AUTH CALLBACK =================
app.get('/auth/callback', async (req, res) => {
  const { shop, code, host } = req.query;

  if (!shop || !code) {
    return res.status(400).send('Missing OAuth parameters');
  }

  if (!verifyOAuthHmac(req.query)) {
    return res.status(401).send('Invalid OAuth HMAC');
  }

  try {
    const tokenRes = await fetch(
      `https://${shop}/admin/oauth/access_token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: SHOPIFY_API_KEY,
          client_secret: SHOPIFY_API_SECRET,
          code
        })
      }
    );

    if (!tokenRes.ok) {
      return res.status(500).send('Failed to exchange token');
    }

    const { access_token } = await tokenRes.json();

    // Register webhooks
    await registerWebhooks(shop, access_token);

    // Redirect to Shopify Admin embedded app
    const embeddedUrl =
      `https://admin.shopify.com/store/${shop.replace('.myshopify.com', '')}` +
      `/apps/${process.env.SHOPIFY_API_KEY}`;

    return res.redirect(embeddedUrl);
  } catch (error) {
    console.error('[AUTH ERROR]', error);
    return res.status(500).send('OAuth failed');
  }
});

// ================= EMBEDDED APP UI =================
app.get('/app', (req, res) => {
  const { shop, host } = req.query;
  if (!shop || !host) return res.status(400).send('Missing params');

  // Required for iframe embedding
  res.setHeader(
    'Content-Security-Policy',
    `frame-ancestors https://${shop} https://admin.shopify.com;`
  );

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sticky Add to Cart</title>
  <script src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 40px;
      background: #f6f6f7;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background: white;
      padding: 40px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    h1 {
      color: #202223;
      margin-top: 0;
    }
    .status {
      padding: 16px;
      background: #d4f5e9;
      border-left: 4px solid #00a47c;
      border-radius: 4px;
      margin: 20px 0;
    }
    button {
      background: #008060;
      color: white;
      border: none;
      padding: 12px 24px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 600;
    }
    button:hover {
      background: #006e52;
    }
    #result {
      margin-top: 20px;
      padding: 12px;
      background: #f1f2f4;
      border-radius: 4px;
      font-family: monospace;
      font-size: 12px;
      display: none;
    }
  </style>
</head>
<body>
  <!-- Automated Check Helper - Added at top as requested -->
  <div style="background: #e3f1df; padding: 15px; margin-bottom: 20px; border: 1px solid #cce5c8; border-radius: 5px;">
    <p style="margin: 0 0 10px 0; color: #008060; font-weight: bold;">Automated Check Helper</p>
    <button id="test-session-token" type="button" style="padding: 10px 20px; background: #008060; color: white; border: none; border-radius: 4px; cursor: pointer;">Test Session Token</button>
  </div>

  <!-- Existing UI Content -->
  <div class="container">
    <h1>✅ Sticky Add to Cart</h1>
    <div class="status">
      <strong>Status:</strong> App installed successfully!
    </div>
    <p><strong>Shop:</strong> ${shop}</p>
    <p>Your sticky add-to-cart feature is now active on your storefront.</p>
    
    <button onclick="testSessionToken()">Test Session Token</button>
    <div id="result"></div>
  </div>

  <script>
    // App Bridge V4 - Initialize with shopify.config
    shopify.config({
      apiKey: '${SHOPIFY_API_KEY}',
      host: '${host}'
    });

    console.log('[APP BRIDGE] Initialized with V4 syntax');

    // Function to get session token (V4 syntax)
    async function getSessionToken() {
      try {
        const token = await shopify.id.getSessionToken();
        console.log('[SESSION TOKEN] Retrieved successfully');
        return token;
      } catch (error) {
        console.error('[SESSION TOKEN] Error:', error);
        throw error;
      }
    }

    // Example: Test session token authentication
    async function testSessionToken() {
      const resultDiv = document.getElementById('result');
      resultDiv.style.display = 'block';
      resultDiv.textContent = 'Loading...';

      try {
        const token = await getSessionToken();
        
        // Make authenticated API call
        const response = await fetch('/api/data', {
          method: 'GET',
          headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
          }
        });

        const data = await response.json();
        resultDiv.textContent = JSON.stringify(data, null, 2);
        resultDiv.style.background = '#d4f5e9';
      } catch (error) {
        resultDiv.textContent = 'Error: ' + error.message;
        resultDiv.style.background = '#ffd6d6';
      }
    }

    // Event listener for automated check helper button (V4 syntax)
    document.getElementById('test-session-token').addEventListener('click', async () => {
      try {
        // New App Bridge V4 syntax
        const token = await shopify.id.getSessionToken();
        console.log('Token generated:', token);
        alert('Success! Session Token Generated.');
      } catch (error) {
        console.error('Token Error:', error);
        alert('Error generating token: ' + error.message);
      }
    });
  </script>
</body>
</html>
  `);
});

// ================= START SERVER =================
app.listen(PORT, () => {
  console.log(`✅ Shopify app server running on port ${PORT}`);
});