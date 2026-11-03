import DatabaseConstructor, { Database } from 'better-sqlite3';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { logger } from '../utils/logger.js';

export interface AuditLogRecord {
  id: number;
  timestamp: number;
  amount_usdc: number;
  recipient: string | null;
  domain: string | null;
  tx_hash: string | null;
  status: 'ALLOWED' | 'BLOCKED';
  reason: string | null;
  calldata: string | null;
  created_at: string;
}

export interface RecordSpendParams {
  amountUsdc: number;
  recipient?: string;
  domain?: string;
  txHash?: string;
  timestamp?: number;
}

export interface RecordBlockedParams {
  amountUsdc?: number;
  recipient?: string;
  domain?: string;
  reason: string;
  calldata?: string;
  timestamp?: number;
}

export class SpendTracker {
  private db: Database;
  private closed = false;

  constructor(dbPath: string = ':memory:') {
    const resolvedPath = SpendTracker.resolvePath(dbPath);

    if (resolvedPath !== ':memory:') {
      const dir = path.dirname(resolvedPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      }
    }

    this.db = new DatabaseConstructor(resolvedPath);
    this.initSchema();
  }

  private static resolvePath(p: string): string {
    if (p === ':memory:') return ':memory:';
    if (p.startsWith('~/')) {
      return path.join(os.homedir(), p.slice(2));
    }
    return path.resolve(p);
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        amount_usdc REAL NOT NULL,
        recipient TEXT,
        domain TEXT,
        tx_hash TEXT,
        status TEXT NOT NULL,
        reason TEXT,
        calldata TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
      CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_logs(status);
    `);
  }

  public recordSpend(params: RecordSpendParams): AuditLogRecord {
    this.assertOpen();
    const now = Date.now();
    const timestamp = params.timestamp ?? now;
    if (!Number.isFinite(timestamp) || timestamp < 0 || timestamp > now + 60_000) {
      throw new Error(`Invalid spend timestamp: ${timestamp}`);
    }
    const isoString = new Date(timestamp).toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO audit_logs (timestamp, amount_usdc, recipient, domain, tx_hash, status, reason, calldata, created_at)
      VALUES (?, ?, ?, ?, ?, 'ALLOWED', NULL, NULL, ?)
    `);

    const result = stmt.run(
      timestamp,
      params.amountUsdc,
      params.recipient || null,
      params.domain || null,
      params.txHash || null,
      isoString
    );

    logger.debug('Recorded allowed spend', {
      amountUsdc: params.amountUsdc,
      recipient: params.recipient,
      txHash: params.txHash,
    });

    return {
      id: Number(result.lastInsertRowid),
      timestamp,
      amount_usdc: params.amountUsdc,
      recipient: params.recipient || null,
      domain: params.domain || null,
      tx_hash: params.txHash || null,
      status: 'ALLOWED',
      reason: null,
      calldata: null,
      created_at: isoString,
    };
  }

  public recordBlocked(params: RecordBlockedParams): AuditLogRecord {
    this.assertOpen();
    const now = Date.now();
    const timestamp = params.timestamp ?? now;
    if (!Number.isFinite(timestamp) || timestamp < 0 || timestamp > now + 60_000) {
      throw new Error(`Invalid blocked record timestamp: ${timestamp}`);
    }
    const isoString = new Date(timestamp).toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO audit_logs (timestamp, amount_usdc, recipient, domain, tx_hash, status, reason, calldata, created_at)
      VALUES (?, ?, ?, ?, NULL, 'BLOCKED', ?, ?, ?)
    `);

    const result = stmt.run(
      timestamp,
      params.amountUsdc ?? 0,
      params.recipient || null,
      params.domain || null,
      params.reason,
      params.calldata || null,
      isoString
    );

    logger.warn('Recorded blocked transaction', {
      reason: params.reason,
      amountUsdc: params.amountUsdc,
      recipient: params.recipient,
      domain: params.domain,
    });

    return {
      id: Number(result.lastInsertRowid),
      timestamp,
      amount_usdc: params.amountUsdc ?? 0,
      recipient: params.recipient || null,
      domain: params.domain || null,
      tx_hash: null,
      status: 'BLOCKED',
      reason: params.reason,
      calldata: params.calldata || null,
      created_at: isoString,
    };
  }

  public getRollingSpend(windowMs: number): number {
    this.assertOpen();
    const cutoff = Date.now() - windowMs;
    const stmt = this.db.prepare(`
      SELECT COALESCE(SUM(amount_usdc), 0.0) as total
      FROM audit_logs
      WHERE status = 'ALLOWED' AND timestamp >= ?
    `);

    const row = stmt.get(cutoff) as { total: number };
    return row.total;
  }

  public getHourlySpend(): number {
    return this.getRollingSpend(60 * 60 * 1000);
  }

  public getDailySpend(): number {
    return this.getRollingSpend(24 * 60 * 60 * 1000);
  }

  public getRecentLogs(
    limit: number = 50,
    filter?: { status?: 'ALLOWED' | 'BLOCKED' }
  ): AuditLogRecord[] {
    this.assertOpen();
    const safeLimit = Math.min(Math.max(1, limit), 1000);
    if (filter?.status) {
      const stmt = this.db.prepare(`
        SELECT id, timestamp, amount_usdc, recipient, domain, tx_hash, status, reason, calldata, created_at
        FROM audit_logs
        WHERE status = ?
        ORDER BY timestamp DESC
        LIMIT ?
      `);
      return stmt.all(filter.status, safeLimit) as AuditLogRecord[];
    }

    const stmt = this.db.prepare(`
      SELECT id, timestamp, amount_usdc, recipient, domain, tx_hash, status, reason, calldata, created_at
      FROM audit_logs
      ORDER BY timestamp DESC
      LIMIT ?
    `);
    return stmt.all(safeLimit) as AuditLogRecord[];
  }

  public clear(): void {
    this.assertOpen();
    this.db.exec('DELETE FROM audit_logs');
  }

  public close(): void {
    if (!this.closed) {
      this.db.close();
      this.closed = true;
    }
  }

  public isClosed(): boolean {
    return this.closed;
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new Error('SpendTracker database connection is closed');
    }
  }
}
