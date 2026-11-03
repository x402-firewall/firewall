import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { PolicyEngine, PolicyViolationError } from '../src/core/PolicyEngine.js';
import { SpendTracker } from '../src/core/SpendTracker.js';
import { SignerManager } from '../src/core/SignerManager.js';
import { USDC_ADDRESSES } from '../src/config/defaults.js';
import type { Address } from 'viem';

describe('PolicyEngine - Deterministic Rule Evaluator', () => {
  let tracker: SpendTracker;
  let engine: PolicyEngine;

  beforeEach(() => {
    // In-memory SQLite for high-speed, isolated unit tests
    tracker = new SpendTracker(':memory:');
    engine = new PolicyEngine(
      {
        network: 'base-sepolia',
        maxPerCallUsdc: 0.05,
        maxHourlyUsdc: 1.00,
        maxDailyUsdc: 5.00,
        allowedDomains: [],
        allowedContracts: [],
        blockUnlimitedApprovals: true,
      },
      tracker
    );
  });

  afterEach(() => {
    tracker.close();
  });

  describe('1. Per-Call Spend Limits', () => {
    it('allows a payment within the per-call cap', () => {
      const result = engine.evaluate({
        amountUsdc: 0.03,
        recipientAddress: '0x1111111111111111111111111111111111111111',
      });

      expect(result.allowed).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('allows a payment exactly at the per-call cap', () => {
      const result = engine.evaluate({
        amountUsdc: 0.05,
      });

      expect(result.allowed).toBe(true);
    });

    it('blocks a payment exceeding the per-call cap', () => {
      const result = engine.evaluate({
        amountUsdc: 0.051,
        recipientAddress: '0x1111111111111111111111111111111111111111',
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Per-call spend limit exceeded');
    });

    it('throws PolicyViolationError when evaluateOrThrow is called on limit breach', () => {
      expect(() => {
        engine.evaluateOrThrow({ amountUsdc: 0.10 });
      }).toThrowError(PolicyViolationError);
    });
  });

  describe('2. Hourly Velocity Caps', () => {
    it('allows multiple calls that sum below maxHourlyUsdc', () => {
      for (let i = 0; i < 10; i++) {
        const evalResult = engine.evaluate({ amountUsdc: 0.05 });
        expect(evalResult.allowed).toBe(true);
        engine.recordAllowedSpend({ amountUsdc: 0.05 });
      }

      // 10 * $0.05 = $0.50 spent out of $1.00 cap
      expect(tracker.getHourlySpend()).toBeCloseTo(0.50);
      const budget = engine.getBudgetStatus();
      expect(budget.remainingHourlyAllowance).toBeCloseTo(0.50);
    });

    it('blocks payments when cumulative hourly spend would exceed limit', () => {
      // Spend $0.98 in 0.04 chunks
      for (let i = 0; i < 20; i++) {
        engine.recordAllowedSpend({ amountUsdc: 0.04 });
      }
      // Spent $0.80

      // Add $0.18 -> Total $0.98
      engine.recordAllowedSpend({ amountUsdc: 0.18 });

      // Current spend: $0.98. Cap: $1.00. Asking for $0.04 -> $1.02 > $1.00 -> Should block
      const result = engine.evaluate({ amountUsdc: 0.04 });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Hourly spend limit exceeded');
    });
  });

  describe('3. Daily Velocity Caps', () => {
    it('blocks payments when cumulative daily spend exceeds limit', () => {
      // Simulate existing daily spend of $4.98 that occurred 2 hours ago (so hourly is 0)
      const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
      engine.recordAllowedSpend({ amountUsdc: 4.98, timestamp: twoHoursAgo });

      expect(tracker.getHourlySpend()).toBe(0);
      expect(tracker.getDailySpend()).toBeCloseTo(4.98);

      // Now asking for $0.05 -> Daily total $5.03 > $5.00 -> Should block with Daily limit reason
      const result = engine.evaluate({ amountUsdc: 0.05 });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Daily spend limit exceeded');
    });
  });

  describe('4. Domain Allowlists', () => {
    let domainEngine: PolicyEngine;

    beforeEach(() => {
      domainEngine = new PolicyEngine(
        {
          allowedDomains: ['api.openai.com', '*.anthropic.com', 'services.example.org'],
        },
        tracker
      );
    });

    it('allows exact domain matches', () => {
      const result = domainEngine.evaluate({
        amountUsdc: 0.01,
        domain: 'api.openai.com',
      });
      expect(result.allowed).toBe(true);
    });

    it('allows wildcard subdomain matches', () => {
      const result = domainEngine.evaluate({
        amountUsdc: 0.01,
        domain: 'api.anthropic.com',
      });
      expect(result.allowed).toBe(true);

      const rootResult = domainEngine.evaluate({
        amountUsdc: 0.01,
        domain: 'anthropic.com',
      });
      expect(rootResult.allowed).toBe(true);
    });

    it('extracts hostnames from full URLs safely', () => {
      const result = domainEngine.evaluate({
        amountUsdc: 0.01,
        domain: 'https://api.openai.com/v1/chat/completions',
      });
      expect(result.allowed).toBe(true);
    });

    it('blocks unlisted domains', () => {
      const result = domainEngine.evaluate({
        amountUsdc: 0.01,
        domain: 'evil-drainer.xyz',
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Domain 'evil-drainer.xyz' is not in allowedDomains list");
    });

    it('blocks requests missing domain when allowlist is configured', () => {
      const result = domainEngine.evaluate({
        amountUsdc: 0.01,
      });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Domain must be specified');
    });
  });

  describe('5. Recipient & Contract Allowlists', () => {
    it('blocks known zero and burn addresses', () => {
      const zeroAddr = '0x0000000000000000000000000000000000000000';
      const result = engine.evaluate({
        amountUsdc: 0.01,
        recipientAddress: zeroAddr,
      });

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('known zero/burn address');
    });

    it('enforces allowedContracts when configured', () => {
      const trustedContract = '0x2222222222222222222222222222222222222222' as Address;
      const restrictedEngine = new PolicyEngine(
        {
          allowedContracts: [trustedContract],
        },
        tracker
      );

      // Trusted contract passes
      const good = restrictedEngine.evaluate({
        amountUsdc: 0.01,
        recipientAddress: trustedContract,
      });
      expect(good.allowed).toBe(true);

      // Unknown contract gets blocked
      const bad = restrictedEngine.evaluate({
        amountUsdc: 0.01,
        recipientAddress: '0x3333333333333333333333333333333333333333',
      });
      expect(bad.allowed).toBe(false);
      expect(bad.reason).toContain('not in allowedContracts list');
    });
  });

  describe('6. SQLite Audit Logging & Spend Tracking', () => {
    it('records both allowed and blocked attempts in audit logs', () => {
      // 1 allowed payment
      engine.recordAllowedSpend({
        amountUsdc: 0.02,
        recipient: '0x1234567890123456789012345678901234567890',
        domain: 'api.service.com',
        txHash: '0xabc123',
      });

      // 1 blocked payment
      engine.evaluate({
        amountUsdc: 0.50, // Exceeds 0.05 limit
        recipientAddress: '0x9999999999999999999999999999999999999999',
        domain: 'malicious.xyz',
      });

      const logs = tracker.getRecentLogs(10);
      expect(logs.length).toBe(2);

      const blockedLog = logs.find((l) => l.status === 'BLOCKED');
      expect(blockedLog).toBeDefined();
      expect(blockedLog?.amount_usdc).toBe(0.50);
      expect(blockedLog?.reason).toContain('Per-call spend limit exceeded');

      const allowedLog = logs.find((l) => l.status === 'ALLOWED');
      expect(allowedLog).toBeDefined();
      expect(allowedLog?.amount_usdc).toBe(0.02);
      expect(allowedLog?.tx_hash).toBe('0xabc123');

      // Verify blocked spend does NOT count against budget
      expect(tracker.getHourlySpend()).toBeCloseTo(0.02);
    });
  });

  describe('7. SignerManager & EIP-3009 Authorization', () => {
    it('generates a valid EIP-3009 TransferWithAuthorization signature for Base Sepolia', async () => {
      const signer = new SignerManager();
      const recipient = '0x4444444444444444444444444444444444444444' as Address;
      const rawValue = 50000n; // 0.05 USDC (6 decimals)

      const payload = await signer.signX402Payment({
        to: recipient,
        value: rawValue,
      });

      expect(payload.from).toBe(signer.getAddress());
      expect(payload.to).toBe(recipient);
      expect(payload.value).toBe('50000');
      expect(payload.signature).toMatch(/^0x[a-fA-F0-9]{130}$/);
      expect(payload.r).toMatch(/^0x[a-fA-F0-9]{64}$/);
      expect(payload.s).toMatch(/^0x[a-fA-F0-9]{64}$/);
      expect([27, 28]).toContain(payload.v);
    });
  });
});
