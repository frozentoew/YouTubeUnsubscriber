const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// LOG_DB_DIR can be overridden via env var — set to /data/db on Railway with a volume
// so the SQLite log database survives deploys/restarts.
const DB_DIR = process.env.LOG_DB_DIR || path.join(__dirname);
const DB_PATH = path.join(DB_DIR, 'logs.db');

fs.mkdirSync(DB_DIR, { recursive: true });

const db = new Database(DB_PATH);

// WAL mode: better write throughput under concurrent reads
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS auth_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    event            TEXT    NOT NULL,
    account          TEXT,
    name             TEXT,
    user_id          TEXT,
    ip               TEXT,
    reason           TEXT,
    error_description TEXT,
    attempted_at     TEXT    NOT NULL,
    succeeded_at     TEXT,
    created_at       TEXT    DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
  );

  CREATE TABLE IF NOT EXISTS unsubscribe_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT    NOT NULL,
    attempted   INTEGER NOT NULL,
    succeeded   INTEGER NOT NULL,
    failed      INTEGER NOT NULL,
    quota_used  INTEGER NOT NULL,
    session_at  TEXT    NOT NULL,
    created_at  TEXT    DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
  );

  -- One row per failed channel, linked to the parent session
  CREATE TABLE IF NOT EXISTS unsubscribe_failures (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES unsubscribe_sessions(id),
    subscription_id TEXT    NOT NULL,
    reason          TEXT    NOT NULL
  );
`);

const stmtInsertAuthEvent = db.prepare(`
  INSERT INTO auth_events
    (event, account, name, user_id, ip, reason, error_description, attempted_at, succeeded_at)
  VALUES
    (@event, @account, @name, @userId, @ip, @reason, @errorDescription, @attemptedAt, @succeededAt)
`);

const stmtInsertSession = db.prepare(`
  INSERT INTO unsubscribe_sessions
    (user_id, attempted, succeeded, failed, quota_used, session_at)
  VALUES
    (@userId, @attempted, @succeeded, @failed, @quotaUsed, @sessionAt)
`);

const stmtInsertFailure = db.prepare(`
  INSERT INTO unsubscribe_failures (session_id, subscription_id, reason)
  VALUES (@sessionId, @subscriptionId, @reason)
`);

// Wraps session + its failures in a single transaction for consistency
const saveSessionTx = db.transaction((sessionData, failures) => {
  const { lastInsertRowid } = stmtInsertSession.run(sessionData);
  for (const f of failures) {
    stmtInsertFailure.run({ sessionId: lastInsertRowid, subscriptionId: f.subscriptionId, reason: f.reason });
  }
});

function saveAuthEvent(data) {
  try {
    stmtInsertAuthEvent.run({
      event:            data.event            ?? null,
      account:          data.account          ?? null,
      name:             data.name             ?? null,
      userId:           data.userId           ?? null,
      ip:               data.ip               ?? null,
      reason:           data.reason           ?? null,
      errorDescription: data.errorDescription ?? null,
      attemptedAt:      data.attemptedAt      ?? new Date().toISOString(),
      succeededAt:      data.succeededAt      ?? null,
    });
  } catch (err) {
    // DB errors must not crash the server — file logs are the primary record
    console.error('[logStore] saveAuthEvent failed:', err.message);
  }
}

function saveUnsubscribeSession(data) {
  try {
    saveSessionTx(
      {
        userId:    data.userId,
        attempted: data.attempted,
        succeeded: data.succeeded,
        failed:    data.failed,
        quotaUsed: data.quotaUsed,
        sessionAt: data.sessionAt ?? new Date().toISOString(),
      },
      Array.isArray(data.failures) ? data.failures : []
    );
  } catch (err) {
    console.error('[logStore] saveUnsubscribeSession failed:', err.message);
  }
}

module.exports = { saveAuthEvent, saveUnsubscribeSession };
