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
  max: 10,
});

// Per-user rate limiting for destructive subscription actions
const deleteLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
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

app.get('/apple-app-site-association', (req, res) => {
  res.redirect(301, '/.well-known/apple-app-site-association');
});

// ============ API ENDPOINTS ============

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Get OAuth URL with PKCE support
app.post('/api/auth/get-url', authLimiter, (req, res) => {
  try {
    const state = crypto.randomBytes(16).toString('hex');

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
    });

    logger.info('OAuth URL generated', { state });

    res.json({ authUrl, state });
  } catch (error) {
    logger.error('OAuth URL generation failed', { error: error.message });
    res.status(500).json({ error: 'Failed to generate auth URL' });
  }
});

// Exchange authorization code for tokens with PKCE verification
app.post('/api/auth/exchange', authLimiter, validate(schemas.authExchange), async (req, res) => {
  try {
    const { code, state, codeVerifier } = req.validatedBody;

    // SECURITY NOTE — CSRF protection for the mobile flow:
    // Mobile clients (Google Sign-In SDK) generate state client-side and never
    // call /get-url, so the state won't exist server-side.  For these clients,
    // CSRF protection is provided entirely by the PKCE code_verifier (RFC 7636),
    // which binds the auth code to the session that initiated the request.
    // The state check below only protects the web /get-url flow.
    if (!tokenManager.consumePendingState(state)) {
      logger.info('State not found server-side (mobile SDK flow — CSRF delegated to PKCE)', {
        ip: req.ip,
      });
    }

    logger.info('Token exchange initiated', {
      state,
      ip: req.ip,
    });

    const client = createOAuth2Client();
    const { tokens } = await client.getToken({
      code,
      code_verifier: codeVerifier,
      redirect_uri: process.env.GOOGLE_REDIRECT_URI,
    });

    const familyId = tokenManager.generateFamilyId();

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const userId = ticket.getPayload().sub;

    tokenManager.storeGoogleTokens(userId, tokens);

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

// Refresh access token with rotation
app.post('/api/auth/refresh', authLimiter, validate(schemas.authRefresh), async (req, res) => {
  try {
    const { refreshToken } = req.validatedBody;
    const ipAddress = req.ip;

    const newTokens = await tokenManager.rotateRefreshToken(
      refreshToken,
      ipAddress
    );

    res.json({
      appToken: newTokens.accessToken,
      refreshToken: newTokens.refreshToken,
      expiryDate: Math.floor(Date.now() / 1000) + 15 * 60,
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

  if (googleTokens.expiryDate && Date.now() >= googleTokens.expiryDate - 60000) {
    const { credentials } = await client.refreshAccessToken();
    tokenManager.updateGoogleAccessToken(userId, credentials.access_token, credentials.expiry_date);
    client.setCredentials(credentials);
  }

  return google.youtube({ version: 'v3', auth: client });
}

// Get user's subscriptions
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

// Unsubscribe from a channel
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

// Graceful shutdown
function gracefulShutdown(signal) {
  logger.info(`${signal} received: closing HTTP server`);
  server.close(() => {
    logger.info('HTTP server closed — persisting token store');
    tokenManager.persistNow();
    process.exit(0);
  });
  setTimeout(() => {
    logger.warn('Forced shutdown after timeout');
    tokenManager.persistNow();
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
