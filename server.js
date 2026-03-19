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
];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
  console.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
  process.exit(1);
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

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? [`https://${process.env.APP_DOMAIN}`]
    : '*',
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Google-Access-Token'],
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
  skipSuccessfulRequests: true,
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

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

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

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Get OAuth URL with PKCE support [web:60]
app.post('/api/auth/get-url', authLimiter, (req, res) => {
  try {
    const state = crypto.randomBytes(16).toString('hex');
    
    const scopes = [
      'https://www.googleapis.com/auth/youtube.force-ssl'
    ];

    const authUrl = oauth2Client.generateAuthUrl({
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

    logger.info('Token exchange initiated', { 
      state,
      ip: req.ip,
    });

    // Exchange code for tokens with explicit redirect_uri
    const { tokens } = await oauth2Client.getToken({
      code,
      code_verifier: codeVerifier,
      redirect_uri: process.env.GOOGLE_REDIRECT_URI, // Explicitly set redirect_uri
    });

    // Generate token family for rotation
    const familyId = tokenManager.generateFamilyId();
    const userId = tokens.access_token.substring(0, 20);

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
      accessToken: tokens.access_token,
      googleRefreshToken: tokens.refresh_token,
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
app.post('/api/auth/refresh', validate(schemas.authRefresh), async (req, res) => {
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

// Get user's subscriptions [web:13]
app.post('/api/subscriptions/list', authenticateToken, validate(schemas.subscriptionsList), async (req, res) => {
  try {
    const accessToken = req.headers['x-google-access-token'];
    if (!accessToken) {
      return res.status(400).json({ error: 'Missing Google access token' });
    }

    oauth2Client.setCredentials({ access_token: accessToken });
    const youtube = google.youtube({ version: 'v3', auth: oauth2Client });

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
app.post('/api/subscriptions/delete', authenticateToken, validate(schemas.subscriptionsDelete), async (req, res) => {
  try {
    const accessToken = req.headers['x-google-access-token'];
    if (!accessToken) {
      return res.status(400).json({ error: 'Missing Google access token' });
    }
    const { subscriptionId } = req.validatedBody;

    oauth2Client.setCredentials({ access_token: accessToken });
    const youtube = google.youtube({ version: 'v3', auth: oauth2Client });

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
  logger.error('Unhandled error', {
    error: error.message,
    stack: error.stack,
    path: req.path,
  });

  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Server started on port ${PORT}`, {
    environment: process.env.NODE_ENV,
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  process.exit(0);
});

