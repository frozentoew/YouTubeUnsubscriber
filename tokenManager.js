const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const logger = require('./logger');

// DB_PATH can be overridden via env var — set to /data/tokens.json on Railway with a volume
const storePath = process.env.DB_PATH || path.join(__dirname, 'tokens.json');

// ── Encryption helpers (AES-256-GCM) ──────────────────────────────────────────

const ENCRYPTION_KEY = process.env.STORE_ENCRYPTION_KEY
  ? Buffer.from(process.env.STORE_ENCRYPTION_KEY, 'hex')
  : null;

if (!ENCRYPTION_KEY) {
  logger.error('STORE_ENCRYPTION_KEY not set — Google OAuth tokens cannot be encrypted at rest. Refusing to start.');
  process.exit(1);
} else if (ENCRYPTION_KEY.length !== 32) {
  logger.error('STORE_ENCRYPTION_KEY must be 32 bytes (64 hex chars) — exiting');
  process.exit(1);
}

function encryptStore(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return JSON.stringify({
    iv: iv.toString('hex'),
    authTag: cipher.getAuthTag().toString('hex'),
    data: encrypted.toString('base64'),
  });
}

function decryptStore(raw) {
  const outer = JSON.parse(raw);
  if (outer.plain !== undefined) {
    // Legacy plaintext store detected — refuse to load it unencrypted.
    // Re-encrypt by letting the caller re-save after this startup.
    logger.warn('Plaintext token store detected — discarding and starting fresh (re-login required)');
    throw new Error('Plaintext store not supported — encryption is now required');
  }
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    ENCRYPTION_KEY,
    Buffer.from(outer.iv, 'hex')
  );
  decipher.setAuthTag(Buffer.from(outer.authTag, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(outer.data, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

// ── Persistence helpers ────────────────────────────────────────────────────────

function loadStore() {
  try {
    if (fs.existsSync(storePath)) {
      const raw = decryptStore(fs.readFileSync(storePath, 'utf8'));
      const data = JSON.parse(raw);

      let usedTokens;
      if (Array.isArray(data.usedTokens)) {
        usedTokens = new Map(data.usedTokens.map(id => [id, '__legacy__']));
      } else {
        usedTokens = new Map(Object.entries(data.usedTokens || {}));
      }

      return {
        families: new Map(
          Object.entries(data.families || {}).map(([k, v]) => [
            k,
            { ...v, tokens: new Set(v.tokens || []) },
          ])
        ),
        usedTokens,
        googleTokens: new Map(Object.entries(data.googleTokens || {})),
        pendingStates: new Map(Object.entries(data.pendingStates || {})),
      };
    }
  } catch (err) {
    logger.error('Failed to load token store, starting fresh', { error: err.message });
  }
  return { families: new Map(), usedTokens: new Map(), googleTokens: new Map(), pendingStates: new Map() };
}

function saveStore() {
  try {
    const data = {
      families: Object.fromEntries(
        [...state.families.entries()].map(([k, v]) => [
          k,
          { ...v, tokens: [...v.tokens] },
        ])
      ),
      usedTokens:   Object.fromEntries(state.usedTokens),
      googleTokens: Object.fromEntries(state.googleTokens),
      pendingStates: Object.fromEntries(state.pendingStates),
    };
    fs.writeFileSync(storePath, encryptStore(JSON.stringify(data)), { encoding: 'utf8', mode: 0o600 });
    try { fs.chmodSync(storePath, 0o600); } catch { /* ignore */ }
  } catch (err) {
    logger.error('Failed to persist token store', { error: err.message });
  }
}

// Load on startup
const state = loadStore();

// ── Token Manager ──────────────────────────────────────────────────────────────

class TokenManager {
  generateFamilyId() {
    return crypto.randomBytes(16).toString('hex');
  }

  generateAccessToken(userId, familyId) {
    return jwt.sign(
      { userId, familyId, type: 'access' },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );
  }

  generateRefreshToken(userId, familyId) {
    const tokenId = crypto.randomBytes(16).toString('hex');

    const refreshToken = jwt.sign(
      { userId, familyId, tokenId, type: 'refresh' },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    if (!state.families.has(familyId)) {
      state.families.set(familyId, {
        userId,
        tokens: new Set(),
        createdAt: Date.now(),
      });
    }
    state.families.get(familyId).tokens.add(tokenId);
    saveStore();

    return refreshToken;
  }

  rotateRefreshToken(refreshToken, ipAddress) {
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch {
      throw new Error('Invalid or expired refresh token');
    }

    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    const { userId, familyId, tokenId } = decoded;

    if (state.usedTokens.has(tokenId)) {
      logger.security('REFRESH_TOKEN_REUSE_DETECTED', { userId, familyId, tokenId, ipAddress });
      this.revokeTokenFamily(familyId);
      throw new Error('Token reuse detected - possible security breach');
    }

    const family = state.families.get(familyId);

    if (!family || !family.tokens.has(tokenId)) {
      logger.security('INVALID_TOKEN_FAMILY', { userId, familyId, ipAddress });
      throw new Error('Invalid token family');
    }

    state.usedTokens.set(tokenId, familyId);
    family.tokens.delete(tokenId);

    const newAccessToken  = this.generateAccessToken(userId, familyId);
    const newRefreshToken = this.generateRefreshToken(userId, familyId);

    logger.info('Token rotated successfully', { userId, familyId });

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  // ── OAuth State Management (CSRF protection) ──────────────────────────────

  storePendingState(stateToken) {
    state.pendingStates.set(stateToken, Date.now() + 10 * 60 * 1000);
    saveStore();
  }

  consumePendingState(stateToken) {
    const expiry = state.pendingStates.get(stateToken);
    if (!expiry) return false;
    state.pendingStates.delete(stateToken);
    saveStore();
    return Date.now() < expiry;
  }

  // ── Google Token Storage ──────────────────────────────────────────────────

  storeGoogleTokens(userId, tokens) {
    state.googleTokens.set(userId, {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiryDate: tokens.expiry_date,
      updatedAt: Date.now(),
    });
    saveStore();
  }

  getGoogleTokens(userId) {
    return state.googleTokens.get(userId) || null;
  }

  updateGoogleAccessToken(userId, accessToken, expiryDate) {
    const existing = state.googleTokens.get(userId);
    if (existing) {
      existing.accessToken = accessToken;
      existing.expiryDate = expiryDate;
      existing.updatedAt = Date.now();
      saveStore();
    }
  }

  removeGoogleTokens(userId) {
    state.googleTokens.delete(userId);
    saveStore();
  }

  revokeTokenFamily(familyId) {
    const family = state.families.get(familyId);
    if (family) {
      family.tokens.forEach(id => state.usedTokens.set(id, familyId));
      state.families.delete(familyId);
      saveStore();
      logger.security('TOKEN_FAMILY_REVOKED', { familyId });
    }
  }

  persistNow() {
    saveStore();
  }

  cleanup() {
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    let removed = 0;
    const deletedFamilyIds = new Set();

    for (const [familyId, family] of state.families.entries()) {
      if (family.createdAt < cutoff) {
        deletedFamilyIds.add(familyId);
        state.families.delete(familyId);
        removed++;
      }
    }

    const previousSize = state.usedTokens.size;
    for (const [tokenId, familyId] of state.usedTokens.entries()) {
      if (deletedFamilyIds.has(familyId) || familyId === '__legacy__') {
        state.usedTokens.delete(tokenId);
      }
    }
    const pruned = previousSize - state.usedTokens.size;

    const now = Date.now();
    for (const [stateToken, expiry] of state.pendingStates.entries()) {
      if (now >= expiry) {
        state.pendingStates.delete(stateToken);
      }
    }

    const activeUserIds = new Set([...state.families.values()].map(f => f.userId));
    for (const userId of state.googleTokens.keys()) {
      if (!activeUserIds.has(userId)) {
        state.googleTokens.delete(userId);
      }
    }

    if (removed > 0 || pruned > 0) {
      saveStore();
    }

    logger.info('Token cleanup completed', { removedFamilies: removed, prunedTokens: pruned });
  }
}

module.exports = new TokenManager();

// Hourly cleanup of expired token families
setInterval(() => module.exports.cleanup(), 60 * 60 * 1000);
