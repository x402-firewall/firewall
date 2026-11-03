#!/usr/bin/env node

import 'dotenv/config';
import { createMcpServer } from './mcp/server.js';
import { FirewallClient } from './client.js';
import { logger } from './utils/logger.js';

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    process.stderr.write(`
x402Firewall — Smart Wallet Firewall & Auto-Pay MCP Server for AI Agents on Base L2

Usage:
  x402-firewall [command]

Commands:
  (default)     Starts the MCP Server using Stdio transport (for Claude Desktop, Cursor, etc.)
  status        Displays current budget caps, rolling spend, and active guardrails/firewall rules
  --help, -h    Displays this help menu

Environment Variables:
  NETWORK                  "base" | "base-sepolia" (default: "base-sepolia")
  RPC_URL                  EVM RPC endpoint URL
  PRIVATE_KEY              32-byte hex signer key (0x...)
  MAX_PER_CALL_USDC        Max spend per single x402 payment (default: 0.05)
  MAX_HOURLY_USDC          Rolling 1-hour cap (default: 1.00)
  MAX_DAILY_USDC           Rolling 24-hour cap (default: 5.00)
  ALLOWED_DOMAINS          Comma-separated allowlisted domains (e.g. api.foo.com,*.bar.org)
  ALLOWED_CONTRACTS        Comma-separated allowlisted EVM contract addresses
  BLOCK_UNLIMITED_APPROVALS Automatically block MAX_UINT256 approvals (default: true)
  ALERT_WEBHOOK_URL        Optional Discord/Telegram webhook for alerts
  DATABASE_PATH            Path to SQLite audit DB (default: ~/.x402firewall/audit.db)
\n`);
    process.exit(0);
  }

  if (args.includes('status') || args.includes('--status')) {
    const client = new FirewallClient();
    const budget = client.getBudgetStatus();
    const address = client.getAddress();
    const policy = client.policyEngine.getPolicy();

    process.stderr.write(`
======================================================
             x402Firewall Status & Budget
======================================================
Agent Address:       ${address}
Target Network:      ${policy.network}
Database Path:       ${policy.databasePath}

Spending Caps:
  • Max Per-Call:    $${budget.maxPerCallUsdc.toFixed(4)} USDC
  • Max Hourly:      $${budget.maxHourlyUsdc.toFixed(4)} USDC
  • Max Daily:       $${budget.maxDailyUsdc.toFixed(4)} USDC

Rolling Spend:
  • Past 1 Hour:     $${budget.currentHourlySpend.toFixed(4)} USDC
  • Past 24 Hours:   $${budget.currentDailySpend.toFixed(4)} USDC

Remaining Allowance:
  • Hourly Remaining: $${budget.remainingHourlyAllowance.toFixed(4)} USDC
  • Daily Remaining:  $${budget.remainingDailyAllowance.toFixed(4)} USDC

Active Firewall Rules:
  • Block Unlimited Approvals: ${policy.blockUnlimitedApprovals ? 'ENABLED' : 'DISABLED'}
  • Allowed Domains:           ${policy.allowedDomains.length ? policy.allowedDomains.join(', ') : 'ALL (if within budget)'}
  • Allowed Contracts:         ${policy.allowedContracts.length ? policy.allowedContracts.join(', ') : 'ALL'}
======================================================
\n`);
    client.close();
    process.exit(0);
  }

  // Default mode: Launch MCP Server on stdio
  const mcp = createMcpServer();
  await mcp.start();
}

main().catch((error) => {
  logger.error('Fatal x402Firewall CLI error', {
    error: error instanceof Error ? error.message : String(error),
  });
  process.exit(1);
});
