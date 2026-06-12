const fs = require('fs');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const logStore = require('./db/logStore');

// LOG_DIR can be overridden via env var — set to /data/logs on Railway with a volume
// so log files survive deploys/restarts.
const LOG_DIR = process.env.LOG_DIR || 'logs';
fs.mkdirSync(LOG_DIR, { recursive: true });

// Spreadsheet-friendly running export of unsubscribe sessions
const CSV_PATH = `${LOG_DIR}/unsubscribe_sessions.csv`;
if (!fs.existsSync(CSV_PATH)) {
  fs.writeFileSync(CSV_PATH, 'session_at,user_id,attempted,succeeded,failed,quota_used\n');
}

// Spreadsheet-friendly running export of auth events
const AUTH_CSV_PATH = `${LOG_DIR}/auth_events.csv`;
if (!fs.existsSync(AUTH_CSV_PATH)) {
  fs.writeFileSync(AUTH_CSV_PATH, 'event,account,name,user_id,ip,reason,error_description,attempted_at,succeeded_at\n');
}

// Escapes a value for inclusion as a single CSV field.
function csvField(value) {
  if (value === undefined || value === null) return '';
  const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/[",\n]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function appendCsvRow(path, values) {
  fs.appendFileSync(path, values.map(csvField).join(',') + '\n');
}

const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'blue',
};

winston.addColors(colors);

const baseFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
  let msg = `${timestamp} [${level}]: ${message}`;
  if (Object.keys(metadata).length > 0) {
    msg += ` | ${JSON.stringify(metadata)}`;
  }
  return msg;
});

const sharedFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  baseFormat
);

const isDev = process.env.NODE_ENV !== 'production';

function makeConsole() {
  return new winston.transports.Console({
    format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
  });
}

// General app log
const appTransport = new DailyRotateFile({
  filename: `${LOG_DIR}/app-%DATE%.log`,
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '7d',
  level: 'info',
});

// Security events (warn+)
const securityTransport = new DailyRotateFile({
  filename: `${LOG_DIR}/security-%DATE%.log`,
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '14d',
  level: 'warn',
});

// Sign-in attempts and results — kept 30 days for audit purposes
const authTransport = new DailyRotateFile({
  filename: `${LOG_DIR}/auth-%DATE%.log`,
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '30d',
  level: 'info',
});

// Unsubscribe session summaries
const activityTransport = new DailyRotateFile({
  filename: `${LOG_DIR}/activity-%DATE%.log`,
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '14d',
  level: 'info',
});

const logger = winston.createLogger({
  levels,
  format: sharedFormat,
  transports: [
    securityTransport,
    appTransport,
    ...(isDev ? [makeConsole()] : []),
  ],
  exitOnError: false,
});

// Writes to logs/auth-*.log
// event: 'ATTEMPT' | 'SUCCESS' | 'FAILED'
// SUCCESS metadata: { account, name, userId }
// FAILED  metadata: { ip, reason, errorDescription? }
const authLogger = winston.createLogger({
  levels,
  format: sharedFormat,
  transports: [
    authTransport,
    ...(isDev ? [makeConsole()] : []),
  ],
  exitOnError: false,
});

// Writes to logs/activity-*.log
// metadata: { userId, attempted, succeeded, failed, failures, quotaUsed }
const activityLogger = winston.createLogger({
  levels,
  format: sharedFormat,
  transports: [
    activityTransport,
    ...(isDev ? [makeConsole()] : []),
  ],
  exitOnError: false,
});

// Replaces all characters after the first 3 with *'s.
// e.g. "john.doe@gmail.com" → "joh****************"
function maskName(value) {
  if (!value || typeof value !== 'string') return value;
  if (value.length <= 3) return value;
  return value.slice(0, 3) + '*'.repeat(value.length - 3);
}

logger.security = (event, metadata) => {
  logger.warn(`SECURITY_EVENT: ${event}`, metadata);
};

// Logs a sign-in lifecycle event to logs/auth-*.log and the auth_events DB table.
// Account names and display names are masked before writing to either destination.
// event: 'ATTEMPT' | 'SUCCESS' | 'FAILED'
logger.authEvent = (event, metadata) => {
  const safe = { ...metadata };
  if (safe.account) safe.account = maskName(safe.account);
  if (safe.name)    safe.name    = maskName(safe.name);

  authLogger.info(`AUTH_${event}`, safe);
  logStore.saveAuthEvent({ event, ...safe });

  try {
    appendCsvRow(AUTH_CSV_PATH, [
      event, safe.account, safe.name, safe.userId, safe.ip,
      safe.reason, safe.errorDescription, safe.attemptedAt, safe.succeededAt,
    ]);
  } catch (err) {
    console.error('[logger] failed to append auth_events.csv:', err.message);
  }
};

// Logs the aggregate result of a bulk-unsubscribe session to logs/activity-*.log,
// the unsubscribe_sessions / unsubscribe_failures DB tables, and
// unsubscribe_sessions.csv for easy spreadsheet viewing.
logger.unsubscribeSession = (metadata) => {
  const sessionAt = new Date().toISOString();

  activityLogger.info('UNSUBSCRIBE_SESSION', metadata);
  logStore.saveUnsubscribeSession({ ...metadata, sessionAt });

  try {
    appendCsvRow(CSV_PATH, [sessionAt, metadata.userId, metadata.attempted, metadata.succeeded, metadata.failed, metadata.quotaUsed]);
  } catch (err) {
    console.error('[logger] failed to append unsubscribe_sessions.csv:', err.message);
  }
};

module.exports = logger;

