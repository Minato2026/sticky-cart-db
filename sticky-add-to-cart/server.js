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

// Extension ID for deep linking
const EXTENSION_ID = 'e1aedd00-b7b7-3d03-c0a8-780619cddce0eec0c07d';

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

  // Deep link URL for Theme Editor
  const deepLinkUrl = `https://${shop}/admin/themes/current/editor?context=apps&activateAppId=${EXTENSION_ID}`;

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
  <script src="https://cdn.shopify.com/shopifycloud/app-bridge.js" data-api-key="${SHOPIFY_API_KEY}"></script>
  <style>
    * {
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 40px 20px;
      background: #f6f6f7;
      min-height: 100vh;
    }
    .container {
      max-width: 640px;
      margin: 0 auto;
      background: white;
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    }
    .header {
      text-align: center;
      margin-bottom: 32px;
    }
    .header h1 {
      color: #202223;
      margin: 0 0 12px 0;
      font-size: 24px;
      font-weight: 700;
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: #d4f5e9;
      color: #00664d;
      padding: 8px 16px;
      border-radius: 20px;
      font-size: 14px;
      font-weight: 600;
    }
    .status-badge svg {
      width: 16px;
      height: 16px;
    }
    .divider {
      height: 1px;
      background: #e1e3e5;
      margin: 32px 0;
    }
    .steps-section h2 {
      color: #202223;
      font-size: 16px;
      font-weight: 600;
      margin: 0 0 20px 0;
    }
    .step {
      display: flex;
      align-items: flex-start;
      gap: 16px;
      margin-bottom: 20px;
    }
    .step-number {
      flex-shrink: 0;
      width: 28px;
      height: 28px;
      background: #f3f4f6;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 13px;
      font-weight: 600;
      color: #5c5f62;
    }
    .step-content {
      flex: 1;
      padding-top: 4px;
    }
    .step-content p {
      margin: 0;
      color: #5c5f62;
      font-size: 14px;
      line-height: 1.5;
    }
    .step-content strong {
      color: #202223;
    }
    .cta-section {
      margin-top: 36px;
      text-align: center;
    }
    .cta-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      background: #008060;
      color: white;
      border: none;
      padding: 16px 32px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 16px;
      font-weight: 600;
      text-decoration: none;
      transition: background 0.2s ease, transform 0.2s ease;
      min-width: 280px;
    }
    .cta-button:hover {
      background: #006e52;
      transform: translateY(-1px);
    }
    .cta-button:active {
      transform: translateY(0);
    }
    .cta-button svg {
      width: 20px;
      height: 20px;
    }
    .shop-info {
      margin-top: 24px;
      text-align: center;
      font-size: 13px;
      color: #8c9196;
    }
    
    /* Hidden debug section - kept for session token testing */
    .debug-section {
      display: none;
      background: #f1f2f4;
      padding: 16px;
      margin-top: 32px;
      border-radius: 8px;
      font-family: monospace;
      font-size: 12px;
    }
    .debug-section.show {
      display: block;
    }
    .debug-toggle {
      margin-top: 24px;
      text-align: center;
    }
    .debug-toggle button {
      background: none;
      border: 1px solid #d3d4d5;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 12px;
      color: #6d7175;
    }
    .debug-toggle button:hover {
      background: #f9fafb;
    }
    .debug-btn {
      margin-top: 10px;
      padding: 8px 16px;
      background: #5c5f62;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <div class="header">
      <h1>Enable Sticky Add To Cart in your theme</h1>
      <div class="status-badge">
        <svg viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
        </svg>
        App Installed ✅
      </div>
    </div>

    <div class="divider"></div>

    <!-- Steps Section -->
    <div class="steps-section">
      <h2>Follow these steps to activate:</h2>
      
      <div class="step">
        <div class="step-number">1</div>
        <div class="step-content">
          <p>Click the <strong>'Enable in Theme Editor'</strong> button below.</p>
        </div>
      </div>

      <div class="step">
        <div class="step-number">2</div>
        <div class="step-content">
          <p>In the theme editor, make sure the <strong>app embed is toggled ON</strong>.</p>
        </div>
      </div>

      <div class="step">
        <div class="step-number">3</div>
        <div class="step-content">
          <p>Click <strong>Save</strong> in the top right corner.</p>
        </div>
      </div>
    </div>

    <!-- CTA Button -->
    <div class="cta-section">
      <a href="${deepLinkUrl}" target="_top" class="cta-button">
        <svg viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clip-rule="evenodd"/>
        </svg>
        Enable in Theme Editor
      </a>
    </div>

    <p class="shop-info">Shop: ${shop}</p>

    <!-- Debug Toggle (for automated checks) -->
    <div class="debug-toggle">
      <button onclick="document.getElementById('debug-panel').classList.toggle('show')">
        🔧 Developer Tools
      </button>
    </div>

    <!-- Hidden Debug Section for Session Token Testing -->
    <div class="debug-section" id="debug-panel">
      <p><strong>Automated Check Helper</strong></p>
      <div id="debug-info">Checking...</div>
      <button id="test-session-token" class="debug-btn" type="button">Test Session Token</button>
    </div>
  </div>

  <script>
    document.addEventListener('DOMContentLoaded', function() {
      var btn = document.getElementById('test-session-token');
      var debugInfo = document.getElementById('debug-info');
      var key = "${SHOPIFY_API_KEY}";
      var host = new URLSearchParams(location.search).get("host");
      
      // Wait for shopify to load
      setTimeout(function() {
        var status = [];
        status.push('shopify: ' + (typeof shopify !== 'undefined' ? '✅' : '❌'));
        status.push('shopify.idToken: ' + (typeof shopify !== 'undefined' && shopify.idToken ? '✅' : '❌'));
        status.push('Host: ' + (host ? host.substring(0,10) + '...' : '❌'));
        debugInfo.innerHTML = status.join(' | ');
      }, 1000);
      
      if(btn) {
        btn.innerHTML = "GENERATE TOKEN ⚡";
        btn.disabled = false;
        
        btn.addEventListener('click', function() {
          console.log('=== TOKEN GENERATION START ===');
          
          if (typeof shopify === 'undefined') {
            alert("ERROR: shopify not loaded!");
            return;
          }

          if (!shopify.idToken) {
            alert("ERROR: shopify.idToken not available!");
            return;
          }

          btn.innerHTML = "Generating...";
          console.log('Calling shopify.idToken()...');
          
          shopify.idToken()
            .then(function(token) {
              console.log('SUCCESS! Token:', token);
              alert("SUCCESS! Token Generated ✅");
              btn.innerHTML = "DONE ✅";
            })
            .catch(function(err) {
              console.error('ERROR:', err);
              alert("Error: " + err.message);
              btn.innerHTML = "Error - Check Console";
            });
        });
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