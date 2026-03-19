const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const logger = require('./logger');

// DB_PATH can be overridden via env var — set to /data/tokens.json on Railway with a volume
const storePath = process.env.DB_PATH || path.join(__dirname, 'tokens.json');

// ── Persistence helpers ────────────────────────────────────────────────────────

function loadStore() {
  try {
    if (fs.existsSync(storePath)) {
      const raw = JSON.parse(fs.readFileSync(storePath, 'utf8'));
      return {
        families:   new Map(Object.entries(raw.families  || {})),
        usedTokens: new Set(raw.usedTokens || []),
      };
    }
  } catch (err) {
    logger.error('Failed to load token store, starting fresh', { error: err.message });
  }
  return { families: new Map(), usedTokens: new Set() };
}

function saveStore() {
  try {
    const data = {
      families:   Object.fromEntries(state.families),
      usedTokens: [...state.usedTokens],
    };
    fs.writeFileSync(storePath, JSON.stringify(data), 'utf8');
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

    // Replay attack: token already used
    if (state.usedTokens.has(tokenId)) {
      logger.security('REFRESH_TOKEN_REUSE_DETECTED', { userId, familyId, tokenId, ipAddress });
      this.revokeTokenFamily(familyId);
      throw new Error('Token reuse detected - possible security breach');
    }

    const family = state.families.get(familyId);

    // Unknown family (revoked or expired)
    if (!family || !family.tokens.has(tokenId)) {
      logger.security('INVALID_TOKEN_FAMILY', { userId, familyId, ipAddress });
      throw new Error('Invalid token family');
    }

    // Mark old token as used and remove from active set
    state.usedTokens.add(tokenId);
    family.tokens.delete(tokenId);

    // Issue new pair
    const newAccessToken  = this.generateAccessToken(userId, familyId);
    const newRefreshToken = this.generateRefreshToken(userId, familyId);

    // generateRefreshToken calls saveStore(); no extra save needed

    logger.info('Token rotated successfully', { userId, familyId });

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  revokeTokenFamily(familyId) {
    const family = state.families.get(familyId);
    if (family) {
      family.tokens.forEach(id => state.usedTokens.add(id));
      state.families.delete(familyId);
      saveStore();
      logger.security('TOKEN_FAMILY_REVOKED', { familyId });
    }
  }

  cleanup() {
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    let removed = 0;

    for (const [familyId, family] of state.families.entries()) {
      if (family.createdAt < cutoff) {
        family.tokens.forEach(id => state.usedTokens.add(id));
        state.families.delete(familyId);
        removed++;
      }
    }

    // Prune usedTokens older than 7 days by keeping only IDs still referenced
    // (they expire naturally via JWT; Set size is bounded by active traffic)
    if (removed > 0) {
      saveStore();
    }

    logger.info('Token cleanup completed', { removedFamilies: removed });
  }
}

module.exports = new TokenManager();

// Hourly cleanup of expired token families
setInterval(() => module.exports.cleanup(), 60 * 60 * 1000);
