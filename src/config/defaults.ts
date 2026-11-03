import type { Network } from './schema.js';

export const CHAIN_IDS: Record<Network, number> = {
  'base': 8453,
  'base-sepolia': 84532,
};

export const DEFAULT_RPC_URLS: Record<Network, string> = {
  'base': 'https://mainnet.base.org',
  'base-sepolia': 'https://sepolia.base.org',
};

export const USDC_ADDRESSES: Record<Network, `0x${string}`> = {
  'base': '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  'base-sepolia': '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
};

export const USDC_DECIMALS = 6;

export const DEFAULT_POLICY_VALUES = {
  network: 'base-sepolia' as Network,
  maxPerCallUsdc: 0.05,
  maxHourlyUsdc: 1.00,
  maxDailyUsdc: 5.00,
  allowedDomains: [] as string[],
  allowedContracts: [] as `0x${string}`[],
  blockUnlimitedApprovals: true,
  databasePath: '~/.x402firewall/audit.db',
};

export const DANGEROUS_SELECTORS = {
  APPROVE: '0x095ea7b3',
  INCREASE_ALLOWANCE: '0x39509351',
  SET_APPROVAL_FOR_ALL: '0xa22cb465',
  PERMIT: '0xd505accf',
  SAFE_TRANSFER_FROM_ERC721: '0x42842e0e',
  TRANSFER_FROM: '0x23b872dd',
  SAFE_TRANSFER_FROM_ERC1155: '0xb88d4fde',
  TRANSFER: '0xa9059cbb',
} as const;

export const KNOWN_BURN_ADDRESSES: `0x${string}`[] = [
  '0x0000000000000000000000000000000000000000',
  '0x000000000000000000000000000000000000dead',
  '0xdead000000000000000000000000000000000000',
];

