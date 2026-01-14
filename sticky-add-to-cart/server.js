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
const HOST = process.env.HOST; // https://your-app.onrender.com
const SCOPES = process.env.SCOPES || 'write_themes';
const API_VERSION = '2024-01';

if (!SHOPIFY_API_KEY || !SHOPIFY_API_SECRET || !HOST) {
  console.error('❌ Missing required environment variables');
  process.exit(1);
}

// ================= WEBHOOK (RAW BODY) =================
// MUST be before body parsers
app.post(
  '/api/webhooks/app-uninstalled',
  express.text({ type: 'application/json' }),
  (req, res) => {
    const hmac = req.headers['x-shopify-hmac-sha256'];
    if (!hmac) return res.status(401).send('Unauthorized');

    const generatedHmac = crypto
      .createHmac('sha256', SHOPIFY_API_SECRET)
      .update(req.body, 'utf8')
      .digest('base64');

    if (generatedHmac !== hmac) {
      return res.status(401).send('Unauthorized');
    }

    return res.status(200).send('OK');
  }
);

// ================= BODY PARSERS =================
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
  await fetch(`https://${shop}/admin/api/${API_VERSION}/webhooks.json`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': accessToken
    },
    body: JSON.stringify({
      webhook: {
        topic: 'app/uninstalled',
        address: `${HOST}/api/webhooks/app-uninstalled`,
        format: 'json'
      }
    })
  });
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

  if (!shop || !code || !host) {
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

    const { access_token } = await tokenRes.json();

    await registerWebhooks(shop, access_token);

    // ✅ CRITICAL REDIRECT (Automated Checks PASS)
    return res.redirect(`/app?shop=${shop}&host=${host}`);
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
  <title>Sticky Add to Cart</title>
  <script src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script>
</head>
<body>
  <h1>✅ App Installed Successfully</h1>

  <script>
    var AppBridge = window['app-bridge'];
    var createApp = AppBridge.default;

    createApp({
      apiKey: '${SHOPIFY_API_KEY}',
      host: '${host}',
      forceRedirect: true
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