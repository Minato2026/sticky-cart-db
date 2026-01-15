// ================= SHOPIFY NODE ADAPTER =================
require('@shopify/shopify-api/adapters/node');

// ================= IMPORTS =================
const express = require('express');
const crypto = require('crypto');
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

// ================= UNIVERSAL WEBHOOK ENDPOINT =================
// CRITICAL: MUST be before body parsers
app.post(
  '/api/webhooks',
  express.text({ type: '*/*' }),
  (req, res) => {
    const hmac = req.headers['x-shopify-hmac-sha256'];
    const topic = req.headers['x-shopify-topic'];
    const shop = req.headers['x-shopify-shop-domain'];

    // Validate HMAC
    if (!hmac) {
      console.error('[WEBHOOK] Missing HMAC header');
      return res.status(401).send('Unauthorized');
    }

    const generatedHmac = crypto
      .createHmac('sha256', SHOPIFY_API_SECRET)
      .update(req.body, 'utf8')
      .digest('base64');

    if (generatedHmac !== hmac) {
      console.error('[WEBHOOK] HMAC verification failed');
      return res.status(401).send('Unauthorized');
    }

    // HMAC valid - log and return 200 immediately
    console.log(`[WEBHOOK] ✅ ${topic} from ${shop}`);

    // Handle specific topics if needed
    if (topic === 'app/uninstalled') {
      console.log(`[WEBHOOK] App uninstalled from ${shop}`);
      // Optional: Clean up data here
    }

    // Always return 200 OK
    return res.status(200).send();
  }
);

// ================= GDPR / PRIVACY WEBHOOKS =================
// Shopify looks specifically for this endpoint
app.post(
  '/webhooks/privacy',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const hmac = req.headers['x-shopify-hmac-sha256'];

    if (!hmac) {
      console.error('[PRIVACY WEBHOOK] ❌ Missing HMAC header');
      return res.status(401).send('Unauthorized');
    }

    const generatedHmac = crypto
      .createHmac('sha256', process.env.SHOPIFY_API_SECRET)
      .update(req.body)
      .digest('base64');

    if (generatedHmac !== hmac) {
      console.error('[PRIVACY WEBHOOK] ❌ HMAC verification failed');
      return res.status(401).send('Unauthorized');
    }

    console.log('[HMAC] ✅ Valid webhook signature');

    const topic = req.headers['x-shopify-topic'];
    const shop = req.headers['x-shopify-shop-domain'];

    console.log(`[PRIVACY] ✅ ${topic}`);

    return res.status(200).send();
  }
);

// ================= BODY PARSERS =================
// CRITICAL: MUST come AFTER webhook route
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
  </style>
</head>
<body>
  <div class="container">
    <h1>✅ Sticky Add to Cart</h1>
    <div class="status">
      <strong>Status:</strong> App installed successfully!
    </div>
    <p><strong>Shop:</strong> ${shop}</p>
    <p>Your sticky add-to-cart feature is now active on your storefront.</p>
  </div>

  <script>
    var AppBridge = window['app-bridge'];
    var createApp = AppBridge.default;

    createApp({
      apiKey: '${SHOPIFY_API_KEY}',
      host: '${host}',
      forceRedirect: true
    });

    console.log('[APP BRIDGE] Initialized');
  </script>
</body>
</html>
  `);
});

// ================= START SERVER =================
app.listen(PORT, () => {
  console.log(`✅ Shopify app server running on port ${PORT}`);
});