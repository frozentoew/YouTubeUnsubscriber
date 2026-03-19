const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define colors for each level
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'blue',
};

winston.addColors(colors);

// Custom format for security events
const securityFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
  let msg = `${timestamp} [${level}]: ${message}`;
  
  if (Object.keys(metadata).length > 0) {
    msg += ` | ${JSON.stringify(metadata)}`;
  }
  
  return msg;
});

// File rotation for security logs
const securityTransport = new DailyRotateFile({
  filename: 'logs/security-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '14d',
  level: 'warn',
});

// File rotation for general logs
const appTransport = new DailyRotateFile({
  filename: 'logs/app-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '7d',
  level: 'info',
});

// Console transport for development
const consoleTransport = new winston.transports.Console({
  format: winston.format.combine(
    winston.format.colorize(),
    winston.format.simple()
  ),
});

// Create logger instance
const logger = winston.createLogger({
  levels,
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    securityFormat
  ),
  transports: [
    securityTransport,
    appTransport,
    ...(process.env.NODE_ENV !== 'production' ? [consoleTransport] : []),
  ],
  exitOnError: false,
});

// Security event logger
logger.security = (event, metadata) => {
  logger.warn(`SECURITY_EVENT: ${event}`, metadata);
};

module.exports = logger;

