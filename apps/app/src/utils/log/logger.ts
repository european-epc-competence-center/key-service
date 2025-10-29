// Simple console-based logger to replace Winston

// Define which level to log based on environment
const getLogLevel = () => {
  const env = process.env.NODE_ENV || "development";
  const isDevelopment = env === "development";
  return isDevelopment ? "debug" : "warn";
};

// Helper function to format log messages with timestamp and level
const formatMessage = (level: string, message: string, meta?: any): string => {
  const timestamp = new Date().toISOString().replace("T", " ").substring(0, 23);
  const metaStr = meta ? ` ${JSON.stringify(meta)}` : "";
  return `${timestamp} ${level.toUpperCase()}: ${message}${metaStr}`;
};

// Determine current log level priority
const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

const currentLevel = getLogLevel();
const currentLevelPriority =
  logLevels[currentLevel as keyof typeof logLevels] || 1;

// Check if we should log based on current level
const shouldLog = (level: keyof typeof logLevels): boolean => {
  return logLevels[level] <= currentLevelPriority;
};

// Console-based logger instance with same interface as Winston logger
const logger = {
  error: (message: string, meta?: any) => {
    if (shouldLog("error")) {
      console.error(formatMessage("error", message, meta));
    }
  },
  warn: (message: string, meta?: any) => {
    if (shouldLog("warn")) {
      console.warn(formatMessage("warn", message, meta));
    }
  },
  info: (message: string, meta?: any) => {
    if (shouldLog("info")) {
      console.info(formatMessage("info", message, meta));
    }
  },
  http: (message: string, meta?: any) => {
    if (shouldLog("http")) {
      console.log(formatMessage("http", message, meta));
    }
  },
  debug: (message: string, meta?: any) => {
    if (shouldLog("debug")) {
      console.debug(formatMessage("debug", message, meta));
    }
  },
};

// Create a stream object with a 'write' function that will be used by Morgan
export const stream = {
  write: (message: string) => {
    if (shouldLog("http")) {
      console.log(formatMessage("http", message.trim()));
    }
  },
};

// Export the logger instance
export default logger;

// Export convenience methods
export const logError = (message: string, meta?: any) => {
  logger.error(message, meta);
};

export const logWarn = (message: string, meta?: any) => {
  logger.warn(message, meta);
};

export const logInfo = (message: string, meta?: any) => {
  logger.info(message, meta);
};

export const logHttp = (message: string, meta?: any) => {
  logger.http(message, meta);
};

export const logDebug = (message: string, meta?: any) => {
  logger.debug(message, meta);
};
