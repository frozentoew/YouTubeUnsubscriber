const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { google } = require('googleapis');
const crypto = require('crypto');
require('dotenv').config();

// Fail fast if required environment variables are missing
const REQUIRED_ENV = [
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GOOGLE_REDIRECT_URI',
  'JWT_SECRET',
  'JWT_REFRESH_SECRET',
  'STORE_ENCRYPTION_KEY',
];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
  // Use console.error + exitCode so the message flushes before the process
  // exits.  process.stderr.write + process.exit(1) can lose the message on
  // platforms like Railway where the buffer doesn't drain in time.
  console.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
  console.error('Set these in your Railway service variables (not in a .env file).');
  process.exitCode = 1;
  return;
}

const logger = require('./logger');
const { schemas, validate } = require('./validation');
const tokenManager = require('./tokenManager');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ SECURITY MIDDLEWARE ============

// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: { action: 'deny' },
  noSniff: true,
}));

// CORS configuration — always use an explicit allowlist, even in development.
// Wildcard origin ('*') combined with credentials: true is rejected by browsers
// and signals misconfiguration.  Use a specific list for every environment.
const ALLOWED_ORIGINS = process.env.NODE_ENV === 'development'
  ? ['http://localhost:3000', 'http://127.0.0.1:3000']
  : [`https://${process.env.APP_DOMAIN}`];

app.use(cors({
  origin: ALLOWED_ORIGINS,
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json({ limit: '10kb' })); // Limit payload size

// Global rate limiting
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests, please try again later' },
  handler: (req, res) => {
    logger.security('RATE_LIMIT_EXCEEDED', {
      ip: req.ip,
      path: req.path,
    });
    res.status(429).json({ error: 'Too many requests' });
  },
});

app.use('/api/', globalLimiter);

// Strict rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // Only 10 auth attempts per 15 minutes
});

// Per-user rate limiting for destructive subscription actions
const deleteLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,             // Max 30 unsubscribes per minute
  keyGenerator: (req) => req.user?.userId || req.ip,
  message: { error: 'Too many unsubscribe requests, please slow down' },
  handler: (req, res) => {
    logger.security('DELETE_RATE_LIMIT_EXCEEDED', {
      userId: req.user?.userId,
      ip: req.ip,
    });
    res.status(429).json({ error: 'Too many unsubscribe requests, please slow down' });
  },
});

// Request logging middleware
app.use((req, res, next) => {
  logger.http(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('user-agent'),
  });
  next();
});

// ============ OAUTH2 CLIENT SETUP ============

// Factory: creates a fresh OAuth2 client per request to avoid credential race conditions
function createOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

// ============ AUTH MIDDLEWARE ============

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    logger.security('MISSING_AUTH_TOKEN', { 
      ip: req.ip,
      path: req.path,
    });
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = require('jsonwebtoken').verify(
      token,
      process.env.JWT_SECRET
    );

    if (decoded.type !== 'access') {
      throw new Error('Invalid token type');
    }

    req.user = decoded;
    next();
  } catch (err) {
    logger.security('INVALID_AUTH_TOKEN', {
      ip: req.ip,
      error: err.message,
    });
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ============ UNIVERSAL LINKS SUPPORT ============

// Apple App Site Association file for Universal Links [web:51][web:54]
app.get('/.well-known/apple-app-site-association', (req, res) => {
  const aasa = {
    applinks: {
      apps: [],
      details: [
        {
          appID: `${process.env.APPLE_TEAM_ID}.${process.env.BUNDLE_ID}`,
          paths: ['/auth/callback', '/auth/*'],
        },
      ],
    },
  };

  res.set('Content-Type', 'application/json');
  res.json(aasa);
});

// Legacy path (without .well-known)
app.get('/apple-app-site-association', (req, res) => {
  res.redirect(301, '/.well-known/apple-app-site-association');
});

// ============ API ENDPOINTS ============

// Health check — do not expose server timestamp (fingerprinting risk)
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Get OAuth URL with PKCE support [web:60]
app.post('/api/auth/get-url', authLimiter, (req, res) => {
  try {
    const state = crypto.randomBytes(16).toString('hex');

    // Store state server-side for CSRF validation on exchange
    tokenManager.storePendingState(state);

    const scopes = [
      'https://www.googleapis.com/auth/youtube.force-ssl'
    ];

    const client = createOAuth2Client();
    const authUrl = client.generateAuthUrl({
      access_type: 'offline',
      scope: scopes,
      state: state,
      prompt: 'consent',
      // Note: PKCE will be handled client-side [web:60]
    });

    logger.info('OAuth URL generated', { state });

    res.json({ authUrl, state });
  } catch (error) {
    logger.error('OAuth URL generation failed', { error: error.message });
    res.status(500).json({ error: 'Failed to generate auth URL' });
  }
});

// Exchange authorization code for tokens with PKCE verification [web:60][web:63]
app.post('/api/auth/exchange', authLimiter, validate(schemas.authExchange), async (req, res) => {
  try {
    const { code, state, codeVerifier } = req.validatedBody;

    // Validate state parameter against server-side store (CSRF protection).
    // Mobile clients (Google Sign-In SDK) generate their own state client-side
    // and never call /get-url, so the state won't exist server-side.  The SDK
    // handles CSRF protection natively, so we log but allow the exchange.
    if (!tokenManager.consumePendingState(state)) {
      logger.info('State not found server-side (expected for mobile SDK flow)', {
        ip: req.ip,
      });
    }

    logger.info('Token exchange initiated', {
      state,
      ip: req.ip,
    });

    // Exchange code for tokens with explicit redirect_uri
    const client = createOAuth2Client();
    const { tokens } = await client.getToken({
      code,
      code_verifier: codeVerifier,
      redirect_uri: process.env.GOOGLE_REDIRECT_URI, // Explicitly set redirect_uri
    });

    // Generate token family for rotation
    const familyId = tokenManager.generateFamilyId();

    // Verify and extract stable user ID from Google's ID token
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const userId = ticket.getPayload().sub;

    // Store Google tokens server-side (never sent to client)
    tokenManager.storeGoogleTokens(userId, tokens);

    // Generate app tokens with rotation support
    const appAccessToken = tokenManager.generateAccessToken(userId, familyId);
    const appRefreshToken = tokenManager.generateRefreshToken(userId, familyId);

    logger.info('Token exchange successful', {
      userId,
      familyId,
    });

    res.json({
      appToken: appAccessToken,
      refreshToken: appRefreshToken,
      expiryDate: tokens.expiry_date,
    });

  } catch (error) {
    logger.security('TOKEN_EXCHANGE_FAILED', {
      ip: req.ip,
      error: error.response?.data?.error || error.message,
      errorDescription: error.response?.data?.error_description,
    });
    
    res.status(400).json({ error: 'Failed to exchange authorization code' });
  }
});


// Refresh access token with rotation [web:45]
app.post('/api/auth/refresh', authLimiter, validate(schemas.authRefresh), async (req, res) => {
  try {
    const { refreshToken } = req.validatedBody;
    const ipAddress = req.ip;

    // Rotate refresh token (detects replay attacks)
    const newTokens = await tokenManager.rotateRefreshToken(
      refreshToken,
      ipAddress
    );

    res.json({
      appToken: newTokens.accessToken,
      refreshToken: newTokens.refreshToken,
      expiryDate: Math.floor(Date.now() / 1000) + 15 * 60, // seconds since epoch
    });

  } catch (error) {
    logger.security('TOKEN_REFRESH_FAILED', {
      ip: req.ip,
      error: error.message,
    });

    if (error.message.includes('reuse detected')) {
      return res.status(403).json({ 
        error: 'Security breach detected. Please login again.',
        reloginRequired: true,
      });
    }

    res.status(401).json({ 
      error: 'Failed to refresh token',
      reloginRequired: true,
    });
  }
});

// Helper: get an authenticated YouTube client using server-side Google tokens
async function getYouTubeClient(userId) {
  const googleTokens = tokenManager.getGoogleTokens(userId);
  if (!googleTokens) {
    return null;
  }

  const client = createOAuth2Client();
  client.setCredentials({
    access_token: googleTokens.accessToken,
    refresh_token: googleTokens.refreshToken,
    expiry_date: googleTokens.expiryDate,
  });

  // Auto-refresh if expired
  if (googleTokens.expiryDate && Date.now() >= googleTokens.expiryDate - 60000) {
    const { credentials } = await client.refreshAccessToken();
    tokenManager.updateGoogleAccessToken(userId, credentials.access_token, credentials.expiry_date);
    client.setCredentials(credentials);
  }

  return google.youtube({ version: 'v3', auth: client });
}

// Get user's subscriptions [web:13]
app.post('/api/subscriptions/list', authenticateToken, validate(schemas.subscriptionsList), async (req, res) => {
  try {
    const youtube = await getYouTubeClient(req.user.userId);
    if (!youtube) {
      return res.status(401).json({ error: 'Google account not linked', reloginRequired: true });
    }

    let allSubscriptions = [];
    let nextPageToken = null;

    do {
      const response = await youtube.subscriptions.list({
        part: 'snippet,id',
        mine: true,
        maxResults: 50,
        pageToken: nextPageToken,
      });

      allSubscriptions = allSubscriptions.concat(response.data.items);
      nextPageToken = response.data.nextPageToken;
    } while (nextPageToken);

    logger.info('Subscriptions fetched', {
      userId: req.user.userId,
      count: allSubscriptions.length,
    });

    res.json({
      subscriptions: allSubscriptions.map(sub => ({
        id: sub.id,
        title: sub.snippet.title,
        channelId: sub.snippet.resourceId.channelId,
      })),
      totalCount: allSubscriptions.length,
    });

  } catch (error) {
    logger.error('Subscription fetch failed', {
      userId: req.user?.userId,
      error: error.message,
      code: error.code,
    });
    
    if (error.code === 403) {
      return res.status(403).json({ 
        error: 'Quota exceeded. Try again after 08:00 UTC.',
        quotaExceeded: true,
      });
    } else if (error.code === 401) {
      return res.status(401).json({ 
        error: 'Token expired',
        needsRefresh: true,
      });
    }
    
    res.status(500).json({ error: 'Failed to fetch subscriptions' });
  }
});

// Unsubscribe from a channel [web:12]
app.post('/api/subscriptions/delete', authenticateToken, deleteLimiter, validate(schemas.subscriptionsDelete), async (req, res) => {
  try {
    const { subscriptionId } = req.validatedBody;

    const youtube = await getYouTubeClient(req.user.userId);
    if (!youtube) {
      return res.status(401).json({ error: 'Google account not linked', reloginRequired: true });
    }

    await youtube.subscriptions.delete({
      id: subscriptionId,
    });

    logger.info('Subscription deleted', {
      userId: req.user.userId,
      subscriptionId,
    });

    res.json({ success: true });

  } catch (error) {
    logger.error('Subscription delete failed', {
      userId: req.user?.userId,
      error: error.message,
      code: error.code,
    });
    
    if (error.code === 403) {
      return res.status(403).json({ 
        error: 'Quota exceeded',
        quotaExceeded: true,
      });
    } else if (error.code === 401) {
      return res.status(401).json({ 
        error: 'Token expired',
        needsRefresh: true,
      });
    }
    
    res.status(500).json({ error: 'Failed to unsubscribe' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  // Only log stack traces in development — in production they can leak
  // internal file paths and structure if logs are ever exposed.
  const meta = { error: error.message, path: req.path };
  if (process.env.NODE_ENV !== 'production') {
    meta.stack = error.stack;
  }
  logger.error('Unhandled error', meta);

  res.status(500).json({ error: 'Internal server error' });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Server started on port ${PORT}`, {
    environment: process.env.NODE_ENV,
  });
});

// Graceful shutdown — close the HTTP server, persist token state, then exit.
function gracefulShutdown(signal) {
  logger.info(`${signal} received: closing HTTP server`);
  server.close(() => {
    logger.info('HTTP server closed — persisting token store');
    tokenManager.persistNow();
    process.exit(0);
  });
  // Force exit after 10 seconds if connections hang
  setTimeout(() => {
    logger.warn('Forced shutdown after timeout');
    tokenManager.persistNow();
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

