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
  methods: ['GET', 'POST', 'DELETE'],
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

// One batch-delete session per user per minute — prevents concurrent batch runs
const batchDeleteLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1,
  keyGenerator: (req) => req.user?.userId || req.ip,
  handler: (req, res) => {
    logger.security('BATCH_DELETE_RATE_LIMIT_EXCEEDED', {
      userId: req.user?.userId,
      ip: req.ip,
    });
    res.status(429).json({ error: 'A batch unsubscribe is already in progress. Please wait.' });
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
  const attemptedAt = new Date().toISOString();

  try {
    const { code, state, codeVerifier } = req.validatedBody;

    // CSRF protection: all clients (mobile and web) must present a server-issued
    // state token obtained from POST /api/auth/get-url before initiating OAuth.
    // This ensures the exchange request was initiated by code that first talked
    // to our backend, preventing cross-site request forgery via crafted redirects.
    if (!tokenManager.consumePendingState(state)) {
      logger.security('INVALID_OAUTH_STATE', { ip: req.ip });
      logger.authEvent('FAILED', {
        ip: req.ip,
        reason: 'Invalid or expired OAuth state',
        attemptedAt,
      });
      return res.status(400).json({ error: 'Invalid or expired OAuth state' });
    }

    logger.authEvent('ATTEMPT', { ip: req.ip, attemptedAt });

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
    const payload = ticket.getPayload();
    const userId = payload.sub;

    tokenManager.storeGoogleTokens(userId, tokens);

    const appAccessToken = tokenManager.generateAccessToken(userId, familyId);
    const appRefreshToken = tokenManager.generateRefreshToken(userId, familyId);

    logger.authEvent('SUCCESS', {
      account: payload.email,
      name: payload.name,
      userId,
      attemptedAt,
      succeededAt: new Date().toISOString(),
    });

    logger.info('Token exchange successful', { userId, familyId });

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
    logger.authEvent('FAILED', {
      ip: req.ip,
      reason: error.response?.data?.error || error.message,
      errorDescription: error.response?.data?.error_description,
      attemptedAt,
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
// Retry transient upstream failures (Google 5xx, dropped connections) with
// exponential backoff. Auth (401) and quota (403) errors are NOT transient and
// are re-thrown immediately so callers can handle them as before.
async function withRetry(fn, { retries = 3, baseDelayMs = 300 } = {}) {
  const TRANSIENT_NET = ['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'EPIPE'];
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      const status = typeof err.code === 'number' ? err.code : err.response?.status;
      const isTransient = (status >= 500 && status <= 599) || TRANSIENT_NET.includes(err.code);
      if (!isTransient || attempt === retries) throw err;
      await new Promise((resolve) => setTimeout(resolve, baseDelayMs * 2 ** attempt));
    }
  }
  throw lastError;
}

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
    const { credentials } = await withRetry(() => client.refreshAccessToken());
    tokenManager.updateGoogleAccessToken(userId, credentials.access_token, credentials.expiry_date);
    client.setCredentials(credentials);
  }

  return google.youtube({ version: 'v3', auth: client });
}

// Get user's subscriptions
app.post('/api/subscriptions/list', authenticateToken, validate(schemas.subscriptionsList), async (req, res) => {
  // Declared outside the try so the catch block can reference it (e.g. when
  // logging how many pages were fetched before a quota error).
  let pagesFetched = 0;
  try {
    const youtube = await getYouTubeClient(req.user.userId);
    if (!youtube) {
      return res.status(401).json({ error: 'Google account not linked', reloginRequired: true });
    }

    let allSubscriptions = [];
    let nextPageToken = null;

    do {
      const response = await withRetry(() => youtube.subscriptions.list({
        part: 'snippet,id',
        mine: true,
        maxResults: 50,
        pageToken: nextPageToken,
      }));

      pagesFetched++;
      allSubscriptions = allSubscriptions.concat(response.data.items);
      nextPageToken = response.data.nextPageToken;
    } while (nextPageToken);

    logger.info('Subscriptions fetched', {
      userId: req.user.userId,
      count: allSubscriptions.length,
      apiUnitsUsed: pagesFetched,         // 1 unit per page request
      totalPages: pagesFetched,
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
      logger.warn('QUOTA_EXCEEDED', {
        endpoint: 'subscriptions/list',
        userId: req.user?.userId,
        apiUnitsUsedBeforeHit: pagesFetched ?? 0,
      });
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
      apiUnitsUsed: 50,   // subscriptions.delete costs 50 units
    });

    logger.unsubscribeSession({
      userId: req.user.userId,
      attempted: 1,
      succeeded: 1,
      failed: 0,
      failures: [],
      quotaUsed: 50,
    });

    res.json({ success: true });

  } catch (error) {
    logger.error('Subscription delete failed', {
      userId: req.user?.userId,
      error: error.message,
      code: error.code,
    });

    const reason =
      error.response?.data?.error?.errors?.[0]?.reason ||
      error.response?.data?.error?.message ||
      error.message;

    logger.unsubscribeSession({
      userId: req.user?.userId,
      attempted: 1,
      succeeded: 0,
      failed: 1,
      failures: [{ subscriptionId: req.validatedBody?.subscriptionId, reason }],
      quotaUsed: 50,
    });

    if (error.code === 403) {
      logger.warn('QUOTA_EXCEEDED', {
        endpoint: 'subscriptions/delete',
        userId: req.user?.userId,
        subscriptionId: req.validatedBody?.subscriptionId,
      });
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

// Bulk unsubscribe — processes all requested deletions in one call and logs an aggregate session summary.
// quotaUsed reflects every API call that reached YouTube (50 units each), whether it succeeded or not.
// Items skipped after a quota-exhausted abort are NOT counted toward quotaUsed.
app.post('/api/subscriptions/batch-delete', authenticateToken, batchDeleteLimiter, validate(schemas.subscriptionsBatchDelete), async (req, res) => {
  const { subscriptionIds } = req.validatedBody;

  const youtube = await getYouTubeClient(req.user.userId);
  if (!youtube) {
    return res.status(401).json({ error: 'Google account not linked', reloginRequired: true });
  }

  // Stream progress as newline-delimited JSON (NDJSON) so the client can show a
  // live progress bar and stay connected during large runs (100+ channels).
  // Each line is a {type:"progress"} object; the final line is {type:"result"}.
  res.status(200);
  res.setHeader('Content-Type', 'application/x-ndjson');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Accel-Buffering', 'no'); // disable proxy buffering (nginx/Railway)
  res.flushHeaders();

  // Stop early if the client hangs up mid-run instead of writing to a dead socket.
  let aborted = false;
  res.on('close', () => { if (!res.writableEnded) aborted = true; });

  const writeLine = (obj) => res.write(`${JSON.stringify(obj)}\n`);

  const results = {
    attempted: subscriptionIds.length,
    succeeded: 0,
    failed: 0,
    failures: [],
    quotaUsed: 0,
  };

  for (let i = 0; i < subscriptionIds.length; i++) {
    if (aborted) break;
    const subscriptionId = subscriptionIds[i];
    try {
      await youtube.subscriptions.delete({ id: subscriptionId });
      results.succeeded++;
      results.quotaUsed += 50;
    } catch (err) {
      const reason =
        err.response?.data?.error?.errors?.[0]?.reason ||
        err.response?.data?.error?.message ||
        err.message;

      if (err.code === 403) {
        // Quota exhausted — count this call, then skip the rest without hitting the API
        results.quotaUsed += 50;
        results.failed++;
        results.failures.push({ subscriptionId, reason: 'Quota exceeded' });

        for (let j = i + 1; j < subscriptionIds.length; j++) {
          results.failed++;
          results.failures.push({ subscriptionId: subscriptionIds[j], reason: 'Quota exceeded — skipped' });
        }
        break;
      }

      if (err.code === 401) {
        results.quotaUsed += 50;
        results.failed++;
        results.failures.push({ subscriptionId, reason: 'Authentication expired' });

        for (let j = i + 1; j < subscriptionIds.length; j++) {
          results.failed++;
          results.failures.push({ subscriptionId: subscriptionIds[j], reason: 'Authentication expired — skipped' });
        }
        break;
      }

      results.quotaUsed += 50;
      results.failed++;
      results.failures.push({ subscriptionId, reason });
    }

    writeLine({
      type: 'progress',
      completed: results.succeeded + results.failed,
      total: results.attempted,
      succeeded: results.succeeded,
      failed: results.failed,
    });
  }

  logger.unsubscribeSession({
    userId: req.user.userId,
    attempted: results.attempted,
    succeeded: results.succeeded,
    failed: results.failed,
    failures: results.failures,
    quotaUsed: results.quotaUsed,
    aborted,
  });

  if (!aborted) {
    writeLine({ type: 'result', ...results });
  }
  res.end();
});

// Delete account — revokes Google OAuth tokens server-side, wipes all stored
// tokens for this user, and marks all JWT families as consumed. The client is
// responsible for clearing its own Keychain after receiving a 200 response.
app.delete('/api/auth/account', authenticateToken, authLimiter, async (req, res) => {
  const { userId } = req.user;
  try {
    const googleTokens = tokenManager.getGoogleTokens(userId);
    if (googleTokens?.refreshToken) {
      try {
        const client = createOAuth2Client();
        await client.revokeToken(googleTokens.refreshToken);
      } catch (revokeErr) {
        // Token may already be expired or revoked — log and continue with local cleanup.
        logger.warn('Google token revocation failed during account deletion', {
          error: revokeErr.message,
        });
      }
    }

    tokenManager.revokeAllFamiliesForUser(userId);

    logger.security('ACCOUNT_DELETED', { userId });
    res.json({ success: true });
  } catch (error) {
    logger.error('Account deletion failed', { error: error.message });
    res.status(500).json({ error: 'Failed to delete account' });
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
