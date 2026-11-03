import type { FirewallClient } from '../../client.js';

export const budgetStatusToolDefinition = {
  name: 'x402_get_budget',
  description:
    'Inspect current x402 spending limits, rolling hourly and daily spends, and remaining USDC allowances on Base L2.',
  inputSchema: {
    type: 'object',
    properties: {},
  },
};

export async function handleBudgetStatusTool(client: FirewallClient) {
  const budget = client.getBudgetStatus();
  const address = client.getAddress();
  const policy = client.policyEngine.getPolicy();

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            agentAddress: address,
            network: policy.network,
            spendingLimits: {
              maxPerCallUsdc: budget.maxPerCallUsdc,
              maxHourlyUsdc: budget.maxHourlyUsdc,
              maxDailyUsdc: budget.maxDailyUsdc,
            },
            currentSpend: {
              last1HourUsdc: budget.currentHourlySpend,
              last24HoursUsdc: budget.currentDailySpend,
            },
            remainingAllowance: {
              hourlyUsdc: budget.remainingHourlyAllowance,
              dailyUsdc: budget.remainingDailyAllowance,
            },
            securityRules: {
              blockUnlimitedApprovals: policy.blockUnlimitedApprovals,
              allowedDomainsCount: policy.allowedDomains.length,
              allowedContractsCount: policy.allowedContracts.length,
            },
          },
          null,
          2
        ),
      },
    ],
  };
}

