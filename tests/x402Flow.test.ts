import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import type { Address } from 'viem';
import { PolicyEngine, PolicyViolationError } from '../src/core/PolicyEngine.js';
import { SpendTracker } from '../src/core/SpendTracker.js';
import { SignerManager } from '../src/core/SignerManager.js';
import { createFirewallFetch } from '../src/x402/firewallFetch.js';
import { X402Facilitator } from '../src/x402/facilitator.js';

describe('x402 Interceptor & Auto-Pay Flow (Phase 3)', () => {
  let server: http.Server;
  let serverPort: number;
  let serverUrl: string;

  let tracker: SpendTracker;
  let policyEngine: PolicyEngine;
  let signerManager: SignerManager;
  let facilitator: X402Facilitator;

  const MERCHANT_ADDRESS: Address = '0x8888888888888888888888888888888888888888';

  beforeEach(async () => {
    tracker = new SpendTracker(':memory:');
    signerManager = new SignerManager();
    facilitator = new X402Facilitator();

    policyEngine = new PolicyEngine(
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

    // Create mock HTTP server simulating an x402-compliant API provider
    server = http.createServer((req, res) => {
      const url = req.url || '/';

      if (url === '/free') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', access: 'public' }));
        return;
      }

      const paymentHeader = req.headers['x-payment'] as string | undefined;

      if (url === '/paid-header') {
        if (!paymentHeader) {
          const requirements = {
            scheme: 'exact',
            network: 'base-sepolia',
            payTo: MERCHANT_ADDRESS,
            asset: 'USDC',
            maxAmountRequired: 0.04,
          };
          const b64 = Buffer.from(JSON.stringify(requirements)).toString('base64');
          res.writeHead(402, {
            'Content-Type': 'application/json',
            'X-Payment-Required': b64,
          });
          res.end(JSON.stringify({ error: 'Payment Required' }));
          return;
        }

        // Validate payment header
        try {
          const decoded = facilitator.decodeHeader(paymentHeader);
          if (
            decoded.payload.authorization.to.toLowerCase() === MERCHANT_ADDRESS.toLowerCase() &&
            decoded.payload.authorization.signature
          ) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, data: 'premium-content-via-header' }));
            return;
          }
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid payment header' }));
          return;
        }
      }

      if (url === '/paid-body') {
        if (!paymentHeader) {
          res.writeHead(402, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: 'Payment Required',
              paymentRequirements: {
                scheme: 'exact',
                network: 'base-sepolia',
                payTo: MERCHANT_ADDRESS,
                asset: 'USDC',
                maxAmountRequired: 0.03,
              },
            })
          );
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, data: 'premium-content-via-body' }));
        return;
      }

      if (url === '/expensive-trap') {
        // Demands $0.50 USDC (exceeds $0.05 per-call limit)
        res.writeHead(402, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            scheme: 'exact',
            network: 'base-sepolia',
            payTo: MERCHANT_ADDRESS,
            asset: 'USDC',
            maxAmountRequired: 0.50,
          })
        );
        return;
      }

      res.writeHead(404);
      res.end();
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as { port: number };
        serverPort = addr.port;
        serverUrl = `http://127.0.0.1:${serverPort}`;
        resolve();
      });
    });
  });

  afterEach(async () => {
    tracker.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('passes regular free endpoints directly without interception', async () => {
    const firewallFetch = createFirewallFetch({
      policyEngine,
      signerManager,
      facilitator,
    });

    const response = await firewallFetch(`${serverUrl}/free`);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.access).toBe('public');
    expect(tracker.getHourlySpend()).toBe(0);
  });

  it('automatically handles 402 challenge with X-Payment-Required header and retries successfully', async () => {
    const firewallFetch = createFirewallFetch({
      policyEngine,
      signerManager,
      facilitator,
    });

    const response = await firewallFetch(`${serverUrl}/paid-header`);
    expect(response.status).toBe(200);

    const body = await response.json();
    expect(body.success).toBe(true);
    expect(body.data).toBe('premium-content-via-header');

    // Verify spend was recorded
    expect(tracker.getHourlySpend()).toBeCloseTo(0.04);
    const logs = tracker.getRecentLogs(5, { status: 'ALLOWED' });
    expect(logs.length).toBe(1);
    expect(logs[0].amount_usdc).toBe(0.04);
    expect(logs[0].recipient?.toLowerCase()).toBe(MERCHANT_ADDRESS.toLowerCase());
  });

  it('automatically handles 402 challenge with JSON body payment requirements', async () => {
    const firewallFetch = createFirewallFetch({
      policyEngine,
      signerManager,
      facilitator,
    });

    const response = await firewallFetch(`${serverUrl}/paid-body`);
    expect(response.status).toBe(200);

    const body = await response.json();
    expect(body.success).toBe(true);
    expect(body.data).toBe('premium-content-via-body');

    expect(tracker.getHourlySpend()).toBeCloseTo(0.03);
  });

  it('blocks 402 challenge when amount exceeds per-call spend cap ($0.50 > $0.05)', async () => {
    const firewallFetch = createFirewallFetch({
      policyEngine,
      signerManager,
      facilitator,
      throwOnViolation: true,
    });

    await expect(firewallFetch(`${serverUrl}/expensive-trap`)).rejects.toThrowError(
      PolicyViolationError
    );

    // Verify zero dollars spent
    expect(tracker.getHourlySpend()).toBe(0);

    // Verify blocked audit log
    const blockedLogs = tracker.getRecentLogs(5, { status: 'BLOCKED' });
    expect(blockedLogs.length).toBe(1);
    expect(blockedLogs[0].amount_usdc).toBe(0.50);
    expect(blockedLogs[0].reason).toContain('Per-call spend limit exceeded');
  });

  it('blocks payment when domain is not in allowedDomains', async () => {
    const strictDomainEngine = new PolicyEngine(
      {
        allowedDomains: ['api.approved-domain.com'],
      },
      tracker
    );

    const firewallFetch = createFirewallFetch({
      policyEngine: strictDomainEngine,
      signerManager,
      facilitator,
      throwOnViolation: true,
    });

    // 127.0.0.1 is not in allowedDomains
    await expect(firewallFetch(`${serverUrl}/paid-header`)).rejects.toThrowError(
      /not in allowedDomains list/
    );

    expect(tracker.getHourlySpend()).toBe(0);
  });
});

