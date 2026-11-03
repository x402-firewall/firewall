import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { PolicyEngine } from '../src/core/PolicyEngine.js';
import { SpendTracker } from '../src/core/SpendTracker.js';
import { SignerManager } from '../src/core/SignerManager.js';
import { EvmSimulator } from '../src/core/EvmSimulator.js';
import { DANGEROUS_SELECTORS } from '../src/config/defaults.js';
import { isSafeExternalUrl } from '../src/utils/webhook.js';
import { EnvConfigSchema, FirewallPolicySchema } from '../src/config/schema.js';
import { parsePaymentRequirements } from '../src/x402/parser.js';
import { X402Facilitator } from '../src/x402/facilitator.js';
import { FirewallClient } from '../src/client.js';
import { encodeFunctionData, parseUnits, type Address, type Hex } from 'viem';

const erc20Abi = [
  {
    name: 'transfer',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'to', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'boolean' }],
  },
] as const;

describe('Security Hardening & Vulnerability Remediation Tests', () => {
  let tracker: SpendTracker;
  let engine: PolicyEngine;
  let simulator: EvmSimulator;

  const TEST_RECIPIENT: Address = '0x1234567890123456789012345678901234567890';
  const TRUSTED_USDC: Address = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';

  beforeEach(() => {
    tracker = new SpendTracker(':memory:');
    engine = new PolicyEngine(
      {
        network: 'base-sepolia',
        maxPerCallUsdc: 0.05,
        maxHourlyUsdc: 1.00,
        maxDailyUsdc: 5.00,
        allowedDomains: ['api.trusted-service.com'],
        allowedContracts: [TRUSTED_USDC],
        blockUnlimitedApprovals: true,
      },
      tracker
    );
    simulator = new EvmSimulator('base-sepolia');
  });

  afterEach(() => {
    tracker.close();
  });

  describe('1. EVM Selector Hardening', () => {
    it('blocks genuine ERC-1155 safeTransferFrom selector (0xf242432a)', () => {
      // 0xf242432a safeTransferFrom(address,address,uint256,uint256,bytes)
      const calldata = '0xf242432a0000000000000000000000001111111111111111111111111111111111111111' as Hex;
      const inspection = simulator.inspectCalldata(calldata, 0.05, true);
      expect(inspection.isSafe).toBe(false);
      expect(inspection.reason).toContain('Blocked dangerous ERC-1155 safeTransferFrom selector (0xf242432a)');
    });

    it('blocks ERC-1155 safeBatchTransferFrom selector (0x2eb2c2d6)', () => {
      // 0x2eb2c2d6 safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
      const calldata = '0x2eb2c2d60000000000000000000000001111111111111111111111111111111111111111' as Hex;
      const inspection = simulator.inspectCalldata(calldata, 0.05, true);
      expect(inspection.isSafe).toBe(false);
      expect(inspection.reason).toContain('Blocked dangerous ERC-1155 safeBatchTransferFrom selector (0x2eb2c2d6)');
    });

    it('blocks ERC-721 safeTransferFrom with data selector (0xb88d4fde)', () => {
      // 0xb88d4fde safeTransferFrom(address,address,uint256,bytes)
      const calldata = '0xb88d4fde0000000000000000000000001111111111111111111111111111111111111111' as Hex;
      const inspection = simulator.inspectCalldata(calldata, 0.05, true);
      expect(inspection.isSafe).toBe(false);
      expect(inspection.reason).toContain('Blocked dangerous ERC-721 safeTransferFrom selector with data (0xb88d4fde)');
    });
  });

  describe('2. Network Mismatch & Cross-Chain Signing Protection', () => {
    it('SignerManager rejects signX402Payment when network does not match signer network', async () => {
      const signer = new SignerManager(undefined, 'base-sepolia');
      await expect(
        signer.signX402Payment({
          to: TEST_RECIPIENT,
          value: 50000n,
          network: 'base', // Attacker requests mainnet signing from testnet agent
        })
      ).rejects.toThrow(/does not match signer network/);
    });

    it('X402Facilitator rejects createPaymentPayload on network mismatch', async () => {
      const signer = new SignerManager(undefined, 'base-sepolia');
      const facilitator = new X402Facilitator();
      await expect(
        facilitator.createPaymentPayload(
          {
            scheme: 'exact',
            network: 'base', // mainnet requested
            payTo: TEST_RECIPIENT,
            asset: 'USDC',
            maxAmountRequired: 0.05,
            atomicAmount: 50000n,
          },
          signer
        )
      ).rejects.toThrow(/requested network 'base' does not match client signer network 'base-sepolia'/);
    });
  });

  describe('3. SSRF Protection', () => {
    it('blocks loopback and localhost URLs', () => {
      expect(isSafeExternalUrl('http://localhost:8080/webhook')).toBe(false);
      expect(isSafeExternalUrl('http://127.0.0.1:3000/webhook')).toBe(false);
      expect(isSafeExternalUrl('http://127.0.0.2/webhook')).toBe(false);
    });

    it('blocks AWS/cloud metadata URL (169.254.169.254)', () => {
      expect(isSafeExternalUrl('http://169.254.169.254/latest/meta-data/')).toBe(false);
    });

    it('blocks RFC1918 private network ranges', () => {
      expect(isSafeExternalUrl('http://10.0.0.1/admin')).toBe(false);
      expect(isSafeExternalUrl('http://192.168.1.1/router')).toBe(false);
      expect(isSafeExternalUrl('http://172.16.0.1/secret')).toBe(false);
      expect(isSafeExternalUrl('http://172.31.255.255/internal')).toBe(false);
    });

    it('allows valid external HTTPS URLs', () => {
      expect(isSafeExternalUrl('https://discord.com/api/webhooks/123/xyz')).toBe(true);
      expect(isSafeExternalUrl('https://api.telegram.org/bot123/send')).toBe(true);
      expect(isSafeExternalUrl('https://api.x402firewall.com/v1/audit')).toBe(true);
    });
  });

  describe('4. Domain Normalization Edge Cases', () => {
    it('normalizes domain with trailing dots correctly', () => {
      // DNS valid FQDN with trailing dot
      const result = engine.evaluate({
        amountUsdc: 0.01,
        recipientAddress: TRUSTED_USDC,
        domain: 'api.trusted-service.com.',
      });
      expect(result.allowed).toBe(true);
    });

    it('normalizes domain with port and uppercase correctly', () => {
      const result = engine.evaluate({
        amountUsdc: 0.01,
        recipientAddress: TRUSTED_USDC,
        domain: 'API.TRUSTED-SERVICE.COM:443',
      });
      expect(result.allowed).toBe(true);
    });
  });

  describe('5. Concurrency & TOCTOU Race Condition Mitigation', () => {
    it('policyEngine.withLock executes critical sections sequentially', async () => {
      const results: number[] = [];
      const p1 = engine.withLock(async () => {
        await new Promise((resolve) => setTimeout(resolve, 30));
        results.push(1);
        return 1;
      });
      const p2 = engine.withLock(async () => {
        results.push(2);
        return 2;
      });

      await Promise.all([p1, p2]);
      expect(results).toEqual([1, 2]);
    });
  });

  describe('6. Schema Validation Hardening', () => {
    it('rejects Infinity in policy spending caps', () => {
      expect(() => {
        FirewallPolicySchema.parse({
          maxPerCallUsdc: Infinity,
        });
      }).toThrow();
    });

    it('rejects Infinity in EnvConfigSchema', () => {
      expect(() => {
        EnvConfigSchema.parse({
          MAX_PER_CALL_USDC: 'Infinity',
        });
      }).toThrow();
    });

    it('strictly validates ALLOWED_CONTRACTS in EnvConfigSchema', () => {
      expect(() => {
        EnvConfigSchema.parse({
          ALLOWED_CONTRACTS: '0xnotanaddress,0x123',
        });
      }).toThrow();

      const valid = EnvConfigSchema.parse({
        ALLOWED_CONTRACTS: `${TRUSTED_USDC}`,
      });
      expect(valid.ALLOWED_CONTRACTS).toEqual([TRUSTED_USDC.toLowerCase()]);
    });
  });

  describe('7. x402 Parser Hardening', () => {
    it('strips prototype pollution keys from extra', async () => {
      const mockPayload = {
        scheme: 'exact',
        network: 'base-sepolia',
        payTo: TEST_RECIPIENT,
        maxAmountRequired: 0.02,
        __proto__: { polluted: true },
        constructor: 'exploit',
      };

      const response = new Response(JSON.stringify(mockPayload), {
        status: 402,
        headers: { 'Content-Type': 'application/json' },
      });

      const parsed = await parsePaymentRequirements(response);
      expect(parsed.maxAmountRequired).toBe(0.02);
      expect((parsed.extra as any)?.__proto__?.polluted).toBeUndefined();
    });

    it('rejects payment amounts over $1,000,000 USDC sanity limit', async () => {
      const mockPayload = {
        scheme: 'exact',
        network: 'base-sepolia',
        payTo: TEST_RECIPIENT,
        maxAmountRequired: 2_000_000,
      };

      const response = new Response(JSON.stringify(mockPayload), {
        status: 402,
        headers: { 'Content-Type': 'application/json' },
      });

      await expect(parsePaymentRequirements(response)).rejects.toThrow(/Invalid payment amount/);
    });
  });

  describe('8. Calldata Spend Extraction in executeSafeTx', () => {
    it('infers amountUsdc from ERC-20 transfer calldata when amountUsdc is omitted', async () => {
      const client = new FirewallClient({
        policy: {
          network: 'base-sepolia',
          maxPerCallUsdc: 0.05,
          maxHourlyUsdc: 1.00,
          maxDailyUsdc: 5.00,
          blockUnlimitedApprovals: true,
          databasePath: ':memory:',
        },
      });

      // Transfer for 0.10 USDC exceeds per-call cap of 0.05 USDC
      const calldata = encodeFunctionData({
        abi: erc20Abi,
        functionName: 'transfer',
        args: [TEST_RECIPIENT, parseUnits('0.10', 6)],
      });

      // Calling executeSafeTx WITHOUT specifying amountUsdc
      const result = await client.executeSafeTx({
        to: TRUSTED_USDC,
        data: calldata,
        // amountUsdc is omitted!
      });

      expect(result.success).toBe(false);
      expect(result.reason).toContain('Per-call spend limit exceeded: requested $0.1000 USDC > limit of $0.0500 USDC');

      client.close();
    });
  });
});
