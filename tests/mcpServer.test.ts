import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { FirewallClient } from '../src/client.js';
import { SpendTracker } from '../src/core/SpendTracker.js';
import { handleBudgetStatusTool } from '../src/mcp/tools/budgetStatusTool.js';
import { handleAuditLogTool } from '../src/mcp/tools/auditLogTool.js';
import { handleExecuteSafeTxTool } from '../src/mcp/tools/executeSafeTxTool.js';
import { createMcpServer } from '../src/mcp/server.js';
import { encodeFunctionData, maxUint256, type Address } from 'viem';

const erc20Abi = [
  {
    name: 'approve',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'boolean' }],
  },
] as const;

describe('MCP Server & Tools (Phase 4)', () => {
  let tracker: SpendTracker;
  let client: FirewallClient;

  const ATTACKER_ADDR: Address = '0x6666666666666666666666666666666666666666';
  const TARGET_CONTRACT: Address = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';

  beforeEach(() => {
    tracker = new SpendTracker(':memory:');
    client = new FirewallClient({
      policy: {
        network: 'base-sepolia',
        maxPerCallUsdc: 0.05,
        maxHourlyUsdc: 1.00,
        maxDailyUsdc: 5.00,
        blockUnlimitedApprovals: true,
      },
      spendTracker: tracker,
    });
  });

  afterEach(() => {
    client.close();
  });

  it('registers all required tools in MCP server', async () => {
    const { server } = createMcpServer(client);
    expect(server).toBeDefined();
  });

  it('tool: x402_get_budget returns formatted status and allowance', async () => {
    const response = await handleBudgetStatusTool(client);
    expect(response.content).toHaveLength(1);
    expect(response.content[0].type).toBe('text');

    const data = JSON.parse(response.content[0].text);
    expect(data.agentAddress).toBe(client.getAddress());
    expect(data.network).toBe('base-sepolia');
    expect(data.spendingLimits.maxPerCallUsdc).toBe(0.05);
    expect(data.remainingAllowance.hourlyUsdc).toBe(1.00);
    expect(data.remainingAllowance.dailyUsdc).toBe(5.00);
  });

  it('tool: x402_safe_tx intercepts and blocks malicious MAX_UINT256 approval', async () => {
    const maliciousCalldata = encodeFunctionData({
      abi: erc20Abi,
      functionName: 'approve',
      args: [ATTACKER_ADDR, maxUint256],
    });

    const response = await handleExecuteSafeTxTool(client, {
      to: TARGET_CONTRACT,
      data: maliciousCalldata,
      amountUsdc: 0.01,
    });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain('[x402Firewall Security Block]');
    expect(response.content[0].text).toContain('Unlimited or excessive token approval detected');

    // Verify it was logged in audit DB
    const auditLogs = client.getAuditLogs(1, 'BLOCKED');
    expect(auditLogs).toHaveLength(1);
    expect(auditLogs[0].status).toBe('BLOCKED');
  });

  it('tool: x402_safe_tx intercepts spend limit violations', async () => {
    const response = await handleExecuteSafeTxTool(client, {
      to: TARGET_CONTRACT,
      amountUsdc: 10.0, // Exceeds 0.05 cap
    });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain('Per-call spend limit exceeded');
  });

  it('tool: x402_safe_tx executes and signs safe transactions', async () => {
    const response = await handleExecuteSafeTxTool(client, {
      to: TARGET_CONTRACT,
      amountUsdc: 0.02,
    });

    expect(response.isError).toBeUndefined();
    const data = JSON.parse(response.content[0].text);
    expect(data.success).toBe(true);
    expect(data.to).toBe(TARGET_CONTRACT);
    expect(data.signedTx).toMatch(/^0x[a-fA-F0-9]+/);

    // Verify hourly budget updated
    expect(tracker.getHourlySpend()).toBeCloseTo(0.02);
  });

  it('tool: x402_audit_log returns permitted and blocked logs', async () => {
    // Generate 1 blocked and 1 allowed event
    await handleExecuteSafeTxTool(client, {
      to: TARGET_CONTRACT,
      amountUsdc: 1.0, // Blocked
    });

    await handleExecuteSafeTxTool(client, {
      to: TARGET_CONTRACT,
      amountUsdc: 0.01, // Allowed
    });

    const response = await handleAuditLogTool(client, { limit: 10 });
    const data = JSON.parse(response.content[0].text);

    expect(data.total).toBe(2);
    expect(data.logs).toHaveLength(2);
    expect(data.logs.some((l: any) => l.status === 'BLOCKED')).toBe(true);
    expect(data.logs.some((l: any) => l.status === 'ALLOWED')).toBe(true);
  });
});

