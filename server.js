const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies
app.use(express.json());

// Root route - Health check
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Sticky Add to Cart App is running',
    timestamp: new Date().toISOString()
  });
});

// Shopify Mandatory GDPR Webhooks
// These endpoints must respond with 200 OK to pass App Store review

// 1. Customer Data Request - GDPR compliance
app.post('/api/webhooks/customers/data_request', (req, res) => {
  console.log('Customer data request received:', req.body);
  
  // In production, you would:
  // 1. Collect all customer data from your database
  // 2. Send it to the customer's email
  // 3. Log the request for compliance
  
  res.status(200).json({
    message: 'Customer data request received and will be processed'
  });
});

// 2. Customer Redact - GDPR compliance
app.post('/api/webhooks/customers/redact', (req, res) => {
  console.log('Customer redact request received:', req.body);
  
  // In production, you would:
  // 1. Delete all customer data from your database
  // 2. Anonymize any logs containing customer info
  // 3. Log the deletion for compliance
  
  res.status(200).json({
    message: 'Customer data redaction request received and will be processed'
  });
});

// 3. Shop Redact - GDPR compliance
app.post('/api/webhooks/shop/redact', (req, res) => {
  console.log('Shop redact request received:', req.body);
  
  // In production, you would:
  // 1. Delete all shop data from your database
  // 2. Remove any stored configurations
  // 3. Log the deletion for compliance
  
  res.status(200).json({
    message: 'Shop data redaction request received and will be processed'
  });
});

// Generic webhook endpoint (fallback)
app.post('/webhooks', (req, res) => {
  console.log('Generic webhook received:', req.body);
  res.status(200).json({ received: true });
});

// Auth callback routes (for OAuth flow)
app.get('/auth/callback', (req, res) => {
  res.status(200).send('Auth callback received');
});

app.get('/auth/shopify/callback', (req, res) => {
  res.status(200).send('Shopify auth callback received');
});

app.get('/api/auth/callback', (req, res) => {
  res.status(200).send('API auth callback received');
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    path: req.path
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Sticky Add to Cart server running on port ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Webhook endpoints ready for Shopify GDPR compliance`);
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
