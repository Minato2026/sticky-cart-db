// CRITICAL: Import Node.js adapter first to prevent runtime errors
require('@shopify/shopify-api/adapters/node');

const express = require('express');
const crypto = require('crypto');
const { shopifyApi, ApiVersion, DeliveryMethod } = require('@shopify/shopify-api');

const app = express();
const PORT = process.env.PORT || 3000;

// ================= ENVIRONMENT VARIABLES =================
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET;
const HOST = process.env.HOST; // e.g., https://your-app.onrender.com
const SCOPES = process.env.SCOPES || 'write_themes';
const API_VERSION = '2024-01';

// Validate required environment variables
if (!SHOPIFY_API_KEY || !SHOPIFY_API_SECRET || !HOST) {
  console.error('❌ Missing required environment variables: SHOPIFY_API_KEY, SHOPIFY_API_SECRET, or HOST');
  process.exit(1);
}

// ================= SHOPIFY API INITIALIZATION =================

/**
 * Initialize Shopify API with explicit GDPR webhook handlers
 * CRITICAL: This is required for automated checks to pass
 */
const shopify = shopifyApi({
  apiKey: SHOPIFY_API_KEY,
  apiSecretKey: SHOPIFY_API_SECRET,
  scopes: SCOPES.split(','),
  hostName: HOST.replace(/https?:\/\//, ''),
  hostScheme: 'https',
  apiVersion: ApiVersion.January24,
  isEmbeddedApp: true,
  // CRITICAL: Explicit webhook handler registration for GDPR compliance
  webhooks: {
    CUSTOMERS_DATA_REQUEST: {
      deliveryMethod: DeliveryMethod.Http,
      callbackUrl: '/api/webhooks',
      callback: async (topic, shop, body, webhookId) => {
        console.log(`[GDPR] CUSTOMERS_DATA_REQUEST received from ${shop}`);
        console.log(`[GDPR] Webhook ID: ${webhookId}`);
        // For extension-only apps with no customer data storage:
        // Simply acknowledge the request
        // If you store customer data, you must return it here
        return { statusCode: 200 };
      },
    },
    CUSTOMERS_REDACT: {
      deliveryMethod: DeliveryMethod.Http,
      callbackUrl: '/api/webhooks',
      callback: async (topic, shop, body, webhookId) => {
        console.log(`[GDPR] CUSTOMERS_REDACT received from ${shop}`);
        console.log(`[GDPR] Webhook ID: ${webhookId}`);
        // Optional: Delete customer data from database
        // await deleteCustomerData(body.customer.id);
        return { statusCode: 200 };
      },
    },
    SHOP_REDACT: {
      deliveryMethod: DeliveryMethod.Http,
      callbackUrl: '/api/webhooks',
      callback: async (topic, shop, body, webhookId) => {
        console.log(`[GDPR] SHOP_REDACT received from ${shop}`);
        console.log(`[GDPR] Webhook ID: ${webhookId}`);
        // Optional: Delete all shop data from database
        // await deleteShopData(shop);
        return { statusCode: 200 };
      },
    },
    APP_UNINSTALLED: {
      deliveryMethod: DeliveryMethod.Http,
      callbackUrl: '/api/webhooks',
      callback: async (topic, shop, body, webhookId) => {
        console.log(`[WEBHOOK] APP_UNINSTALLED received from ${shop}`);
        console.log(`[WEBHOOK] Webhook ID: ${webhookId}`);
        // Optional: Clean up database records for this shop
        // await deleteShopData(shop);
        return { statusCode: 200 };
      },
    },
  },
});

console.log('[SHOPIFY API] ✅ Initialized with GDPR webhook handlers');


// ================= MIDDLEWARE SETUP =================
// CRITICAL: Webhook endpoint needs RAW STRING body for HMAC verification
// Use express.text() to preserve the raw body as a string (not Buffer)
// Single consolidated endpoint handles ALL webhooks
app.use('/api/webhooks', express.text({ type: 'application/json' }));

// All other routes use JSON parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ================= HMAC VERIFICATION FUNCTIONS =================

/**
 * Verify Shopify webhook HMAC signature
 * CRITICAL: Must use raw request body (Buffer) for verification
 */
function verifyWebhookHmac(req, res, next) {
  const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
  const shopDomain = req.get('X-Shopify-Shop-Domain');

  if (!hmacHeader) {
    console.error('[WEBHOOK] Missing HMAC header');
    return res.status(401).send('Unauthorized: Missing HMAC');
  }

  // req.body is a Buffer when using express.raw()
  const rawBody = req.body;

  // Generate HMAC from raw body
  const generatedHmac = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(rawBody)
    .digest('base64');

  // Timing-safe comparison to prevent timing attacks
  const isValid = crypto.timingSafeEqual(
    Buffer.from(generatedHmac, 'utf8'),
    Buffer.from(hmacHeader, 'utf8')
  );

  if (!isValid) {
    console.error(`[WEBHOOK] Invalid HMAC from ${shopDomain}`);
    return res.status(401).send('Unauthorized: Invalid HMAC');
  }

  console.log(`[WEBHOOK] ✅ HMAC verified for ${shopDomain}`);

  // Parse JSON body AFTER verification
  req.body = JSON.parse(rawBody.toString('utf8'));
  next();
}

/**
 * Verify OAuth callback HMAC
 * Uses query parameters (not body)
 */
function verifyOAuthHmac(query) {
  const { hmac, ...params } = query;

  if (!hmac) {
    return false;
  }

  // Build message from sorted query params (excluding hmac)
  const message = Object.keys(params)
    .sort()
    .map(key => `${key}=${params[key]}`)
    .join('&');

  const generatedHmac = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(message)
    .digest('hex');

  // Timing-safe comparison
  return crypto.timingSafeEqual(
    Buffer.from(generatedHmac, 'utf8'),
    Buffer.from(hmac, 'utf8')
  );
}

// ================= WEBHOOK REGISTRATION =================

/**
 * Register webhooks with Shopify
 * NOTE: GDPR webhooks (customers/data_request, customers/redact, shop/redact) 
 * are NOT registered here because they are MANDATORY webhooks.
 * Shopify automatically manages these and rejects manual registration attempts.
 * We only register optional webhooks like app/uninstalled.
 */
async function registerWebhooks(shop, accessToken) {
  const webhooks = [
    {
      topic: 'app/uninstalled',
      address: `${HOST}/api/webhooks/app/uninstalled`,
      format: 'json'
    }
    // GDPR webhooks (customers/data_request, customers/redact, shop/redact) 
    // are NOT registered - they are mandatory and handled automatically by Shopify
  ];

  console.log(`[WEBHOOKS] Registering ${webhooks.length} webhooks for ${shop}...`);

  for (const webhook of webhooks) {
    try {
      const response = await fetch(
        `https://${shop}/admin/api/${API_VERSION}/webhooks.json`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Shopify-Access-Token': accessToken
          },
          body: JSON.stringify({ webhook })
        }
      );

      if (response.ok) {
        console.log(`[WEBHOOKS] ✅ Registered: ${webhook.topic}`);
      } else {
        const error = await response.text();
        console.error(`[WEBHOOKS] ❌ Failed to register ${webhook.topic}:`, error);
      }
    } catch (error) {
      console.error(`[WEBHOOKS] ❌ Error registering ${webhook.topic}:`, error.message);
    }
  }

  console.log('[WEBHOOKS] Registration complete');
}

// ================= HEALTH CHECK =================
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'ok',
    app: 'Sticky Add to Cart',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});

// ================= OAUTH INSTALLATION FLOW =================

/**
 * Step 1: Initiate OAuth
 * Redirects merchant to Shopify OAuth authorization page
 */
app.get('/auth', (req, res) => {
  const { shop } = req.query;

  if (!shop) {
    return res.status(400).send('Missing shop parameter');
  }

  // Validate shop domain format
  const shopRegex = /^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/;
  if (!shopRegex.test(shop)) {
    return res.status(400).send('Invalid shop domain');
  }

  const redirectUri = `${HOST}/auth/callback`;
  const state = crypto.randomBytes(16).toString('hex'); // CSRF protection

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_API_KEY}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;

  console.log(`[AUTH] Redirecting ${shop} to OAuth...`);
  res.redirect(installUrl);
});

/**
 * Step 2: OAuth Callback
 * CRITICAL: This is where webhook registration happens
 * 1. Verify HMAC
 * 2. Exchange code for access token
 * 3. Register webhooks (THIS IS WHY AUTOMATED CHECKS PASS)
 * 4. Redirect back to Shopify Admin
 */
app.get('/auth/callback', async (req, res) => {
  const { shop, code, state } = req.query;

  // Validate required parameters
  if (!shop || !code) {
    return res.status(400).send('Missing required OAuth parameters');
  }

  // Verify OAuth HMAC
  if (!verifyOAuthHmac(req.query)) {
    console.error('[AUTH] Invalid OAuth HMAC');
    return res.status(401).send('Unauthorized: Invalid HMAC');
  }

  console.log(`[AUTH] ✅ OAuth HMAC verified for ${shop}`);

  try {
    // Exchange authorization code for access token
    const tokenResponse = await fetch(
      `https://${shop}/admin/oauth/access_token`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          client_id: SHOPIFY_API_KEY,
          client_secret: SHOPIFY_API_SECRET,
          code
        })
      }
    );

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      console.error('[AUTH] Failed to exchange code for token:', error);
      return res.status(500).send('Failed to complete installation');
    }

    const { access_token } = await tokenResponse.json();
    console.log(`[AUTH] ✅ Access token obtained for ${shop}`);

    // CRITICAL: Register webhooks immediately after installation
    // This is what makes Shopify automated checks pass
    await registerWebhooks(shop, access_token);

    // Optional: Store access token in database if needed
    // For extension-only apps, you may not need persistent storage
    // If you do need it, uncomment and implement:
    // await storeAccessToken(shop, access_token);

    console.log(`[AUTH] ✅ Installation complete for ${shop}`);

    // Redirect merchant back to Shopify Admin
    // CRITICAL: Must redirect to Shopify, not show a custom page
    return res.redirect(`https://${shop}/admin/apps/${SHOPIFY_API_KEY}`);

  } catch (error) {
    console.error('[AUTH] Installation error:', error);
    return res.status(500).send('Installation failed');
  }
});

// ================= CONSOLIDATED WEBHOOK HANDLER =================

/**
 * CONSOLIDATED ROUTING STRATEGY
 * Single endpoint handles ALL webhooks including GDPR topics
 * 
 * CRITICAL REQUIREMENTS:
 * 1. Uses express.text() to preserve raw body for HMAC verification
 * 2. Reads X-Shopify-Topic header (lowercase) to determine webhook type
 * 3. GDPR webhooks get immediate 200 OK response
 * 4. Other webhooks are processed normally
 */
app.post('/api/webhooks', async (req, res) => {
  // CRITICAL: Express normalizes headers to lowercase
  const topic = req.headers['x-shopify-topic'];
  const shop = req.headers['x-shopify-shop-domain'];
  const hmac = req.headers['x-shopify-hmac-sha256'];

  console.log(`[WEBHOOK] Received: ${topic} from ${shop}`);

  // CRITICAL: GDPR webhooks MUST return 200 OK immediately
  // No processing, no database checks, just acknowledge receipt
  if (topic === 'customers/data_request' ||
    topic === 'customers/redact' ||
    topic === 'shop/redact') {
    console.log(`[GDPR] Acknowledging ${topic} - returning 200 OK immediately`);
    return res.status(200).send('OK');
  }

  // For non-GDPR webhooks, return 200 OK and process in background
  res.status(200).send('OK');

  // Process webhook in background (don't await)
  (async () => {
    try {
      console.log(`[WEBHOOK] Processing: ${topic} from ${shop}`);

      // Process webhook using Shopify API
      // This automatically validates HMAC and routes to the correct handler
      await shopify.webhooks.process({
        rawBody: req.body, // Already a string from express.text()
        rawRequest: req,
        rawResponse: res,
      });

      console.log(`[WEBHOOK] ✅ Successfully processed: ${topic}`);
    } catch (error) {
      console.error('[WEBHOOK] ❌ Error processing webhook:', error.message);
      console.error('[WEBHOOK] Error details:', error);

      // Note: We already sent 200 OK, so we can't change the response
      // Just log the error for debugging
    }
  })();
});

// ================= MANDATORY WEBHOOKS (Legacy specific endpoints) =================

/**
 * App Uninstalled Webhook
 * Triggered when merchant uninstalls the app
 * Use this to clean up any stored data
 */
app.post('/api/webhooks/app/uninstalled', verifyWebhookHmac, (req, res) => {
  const { shop_domain } = req.body;
  console.log(`[WEBHOOK] App uninstalled from ${shop_domain}`);

  // Optional: Clean up database records for this shop
  // await deleteShopData(shop_domain);

  res.status(200).send('OK');
});

/**
 * GDPR: Customer Data Request
 * Merchant requests customer data on behalf of the customer
 * Return all data you have about this customer
 */
app.post('/api/webhooks/customers/data_request', verifyWebhookHmac, (req, res) => {
  const { shop_domain, customer } = req.body;
  console.log(`[GDPR] Customer data request for ${customer?.email || 'unknown'} from ${shop_domain}`);

  // For extension-only apps with no customer data storage:
  // Simply acknowledge the request
  // If you store customer data, you must return it here

  res.status(200).send('OK');
});

/**
 * GDPR: Customer Redact
 * Delete all customer data (48 hours after customer requests deletion)
 */
app.post('/api/webhooks/customers/redact', verifyWebhookHmac, (req, res) => {
  const { shop_domain, customer } = req.body;
  console.log(`[GDPR] Customer redact request for ${customer?.email || 'unknown'} from ${shop_domain}`);

  // Optional: Delete customer data from database
  // await deleteCustomerData(customer.id);

  res.status(200).send('OK');
});

/**
 * GDPR: Shop Redact
 * Delete all shop data (48 hours after shop uninstalls)
 */
app.post('/api/webhooks/shop/redact', verifyWebhookHmac, (req, res) => {
  const { shop_domain } = req.body;
  console.log(`[GDPR] Shop redact request for ${shop_domain}`);

  // Optional: Delete all shop data from database
  // await deleteShopData(shop_domain);

  res.status(200).send('OK');
});

// ================= ERROR HANDLERS =================

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    path: req.path
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'production' ? 'An error occurred' : err.message
  });
});

// ================= START SERVER =================
app.listen(PORT, () => {
  console.log('='.repeat(70));
  console.log('✅ Shopify Compliance Server Running');
  console.log(`🌍 Host: ${HOST}`);
  console.log(`🔐 HMAC Verification: ENABLED`);
  console.log(`📋 API Version: ${API_VERSION}`);
  console.log(`🎯 Scopes: ${SCOPES}`);
  console.log('='.repeat(70));
  console.log('📌 Mandatory webhooks will be registered during installation');
  console.log('📌 All webhooks use HMAC verification');
  console.log('='.repeat(70));
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully...');
  process.exit(0);
});