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

  private sanitizeMeta(meta?: Record<string, unknown>): Record<string, unknown> | undefined {
    if (!meta) return undefined;
    const sensitivePattern = /(?:private_?key|api_?key|secret|password|bearer|auth)/i;
    const sanitized: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(meta)) {
      if (sensitivePattern.test(k)) {
        sanitized[k] = '***REDACTED***';
      } else if (v && typeof v === 'object' && !Array.isArray(v)) {
        sanitized[k] = this.sanitizeMeta(v as Record<string, unknown>);
      } else {
        sanitized[k] = v;
      }
    }
    return sanitized;
  }

  private output(level: LogLevel, message: string, meta?: Record<string, unknown>) {
    if (!this.shouldLog(level)) return;

    const sanitizedMeta = this.sanitizeMeta(meta);
    const logEntry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
      ...(sanitizedMeta && Object.keys(sanitizedMeta).length > 0 ? { meta: sanitizedMeta } : {}),
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

