export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

class Logger {
  private minLevel: LogLevel;

  constructor() {
    const envLevel = (process.env.LOG_LEVEL || 'info').toLowerCase() as LogLevel;
    this.minLevel = LEVEL_PRIORITY[envLevel] !== undefined ? envLevel : 'info';
  }

  public setLevel(level: LogLevel) {
    this.minLevel = level;
  }

  private shouldLog(level: LogLevel): boolean {
    return LEVEL_PRIORITY[level] >= LEVEL_PRIORITY[this.minLevel];
  }

  private output(level: LogLevel, message: string, meta?: Record<string, unknown>) {
    if (!this.shouldLog(level)) return;

    const logEntry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
      ...(meta && Object.keys(meta).length > 0 ? { meta } : {}),
    };

    // CRITICAL FOR MCP: Write exclusively to stderr to protect stdout for JSON-RPC
    process.stderr.write(JSON.stringify(logEntry) + '\n');
  }

  public debug(message: string, meta?: Record<string, unknown>) {
    this.output('debug', message, meta);
  }

  public info(message: string, meta?: Record<string, unknown>) {
    this.output('info', message, meta);
  }

  public warn(message: string, meta?: Record<string, unknown>) {
    this.output('warn', message, meta);
  }

  public error(message: string, meta?: Record<string, unknown>) {
    this.output('error', message, meta);
  }
}

export const logger = new Logger();

