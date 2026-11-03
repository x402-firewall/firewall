import { z } from 'zod';
import { DEFAULT_POLICY_VALUES } from './defaults.js';

export const NetworkSchema = z.enum(['base', 'base-sepolia']);
export type Network = z.infer<typeof NetworkSchema>;

export const AddressSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{40}$/, {
    message: 'Address must be a valid 20-byte EVM hex address with 0x prefix',
  })
  .transform((val) => val.toLowerCase() as `0x${string}`);

export const FirewallPolicySchema = z
  .object({
    network: NetworkSchema.default(DEFAULT_POLICY_VALUES.network),
    maxPerCallUsdc: z.number().positive({ message: 'maxPerCallUsdc must be positive' }).finite({ message: 'maxPerCallUsdc must be finite' }).default(DEFAULT_POLICY_VALUES.maxPerCallUsdc),
    maxHourlyUsdc: z.number().positive({ message: 'maxHourlyUsdc must be positive' }).finite({ message: 'maxHourlyUsdc must be finite' }).default(DEFAULT_POLICY_VALUES.maxHourlyUsdc),
    maxDailyUsdc: z.number().positive({ message: 'maxDailyUsdc must be positive' }).finite({ message: 'maxDailyUsdc must be finite' }).default(DEFAULT_POLICY_VALUES.maxDailyUsdc),
    allowedDomains: z.array(z.string()).default(DEFAULT_POLICY_VALUES.allowedDomains),
    allowedContracts: z.array(AddressSchema).default(DEFAULT_POLICY_VALUES.allowedContracts),
    blockUnlimitedApprovals: z.boolean().default(DEFAULT_POLICY_VALUES.blockUnlimitedApprovals),
    alertWebhookUrl: z.string().url({ message: 'alertWebhookUrl must be a valid URL' }).optional(),
    databasePath: z.string().default(DEFAULT_POLICY_VALUES.databasePath),
  })
  .refine(
    (data) => data.maxPerCallUsdc <= data.maxHourlyUsdc,
    {
      message: 'maxPerCallUsdc cannot exceed maxHourlyUsdc',
      path: ['maxPerCallUsdc'],
    }
  )
  .refine(
    (data) => data.maxHourlyUsdc <= data.maxDailyUsdc,
    {
      message: 'maxHourlyUsdc cannot exceed maxDailyUsdc',
      path: ['maxHourlyUsdc'],
    }
  );

export type FirewallPolicy = z.infer<typeof FirewallPolicySchema>;
export type FirewallPolicyInput = z.input<typeof FirewallPolicySchema>;

// Aliases for backwards compatibility
export const GuardrailPolicySchema = FirewallPolicySchema;
export type GuardrailPolicy = FirewallPolicy;
export type GuardrailPolicyInput = FirewallPolicyInput;

export const EnvConfigSchema = z.object({
  NETWORK: NetworkSchema.optional(),
  RPC_URL: z.string().url().optional(),
  PRIVATE_KEY: z
    .string()
    .regex(/^0x[a-fA-F0-9]{64}$/, 'PRIVATE_KEY must be a 64-character hex string with 0x prefix')
    .optional(),
  MAX_PER_CALL_USDC: z
    .string()
    .transform((val) => parseFloat(val))
    .pipe(z.number().positive().finite())
    .optional(),
  MAX_HOURLY_USDC: z
    .string()
    .transform((val) => parseFloat(val))
    .pipe(z.number().positive().finite())
    .optional(),
  MAX_DAILY_USDC: z
    .string()
    .transform((val) => parseFloat(val))
    .pipe(z.number().positive().finite())
    .optional(),
  ALLOWED_DOMAINS: z
    .string()
    .transform((val) => (val ? val.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean) : []))
    .optional(),
  ALLOWED_CONTRACTS: z
    .string()
    .transform((val) => (val ? val.split(',').map((s) => s.trim()).filter(Boolean) : []))
    .pipe(z.array(AddressSchema))
    .optional(),
  BLOCK_UNLIMITED_APPROVALS: z
    .string()
    .transform((val) => val.toLowerCase() !== 'false')
    .optional(),
  ALERT_WEBHOOK_URL: z.string().url().optional(),
  DATABASE_PATH: z.string().optional(),
});

export type EnvConfig = z.infer<typeof EnvConfigSchema>;

export function createFirewallPolicy(input?: Partial<FirewallPolicyInput>): FirewallPolicy {
  return FirewallPolicySchema.parse(input ?? {});
}

export const createGuardrailPolicy = createFirewallPolicy;

export function loadPolicyFromEnv(env: Record<string, string | undefined> = process.env): FirewallPolicy {
  const parsedEnv = EnvConfigSchema.parse(env);
  return FirewallPolicySchema.parse({
    network: parsedEnv.NETWORK,
    maxPerCallUsdc: parsedEnv.MAX_PER_CALL_USDC,
    maxHourlyUsdc: parsedEnv.MAX_HOURLY_USDC,
    maxDailyUsdc: parsedEnv.MAX_DAILY_USDC,
    allowedDomains: parsedEnv.ALLOWED_DOMAINS,
    allowedContracts: parsedEnv.ALLOWED_CONTRACTS,
    blockUnlimitedApprovals: parsedEnv.BLOCK_UNLIMITED_APPROVALS,
    alertWebhookUrl: parsedEnv.ALERT_WEBHOOK_URL,
    databasePath: parsedEnv.DATABASE_PATH,
  });
}
