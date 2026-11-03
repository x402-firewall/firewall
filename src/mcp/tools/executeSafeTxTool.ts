import { z } from 'zod';
import type { Address, Hex } from 'viem';
import type { FirewallClient } from '../../client.js';

export const ExecuteSafeTxInputSchema = z.object({
  to: z
    .string()
    .regex(/^0x[a-fA-F0-9]{40}$/, { message: 'Must be a valid 20-byte EVM address' })
    .transform((val) => val.toLowerCase() as Address),
  data: z
    .string()
    .regex(/^0x[a-fA-F0-9]*$/, { message: 'Must be valid hex calldata with 0x prefix' })
    .optional()
    .default('0x') as z.ZodType<Hex>,
  value: z
    .string()
    .regex(/^\d+$/, { message: 'Must be Wei value as a numeric string' })
    .optional()
    .transform((val) => (val ? BigInt(val) : 0n)),
  amountUsdc: z.number().nonnegative().optional().default(0),
});

export type ExecuteSafeTxInput = z.infer<typeof ExecuteSafeTxInputSchema>;

export const executeSafeTxToolDefinition = {
  name: 'x402_safe_tx',
  description:
    'Simulate and execute an allowlisted EVM transaction on Base L2. Verifies against spending caps, blocks dangerous selectors (unlimited approvals, drainers), and checks contract allowlists before signing.',
  inputSchema: {
    type: 'object',
    properties: {
      to: {
        type: 'string',
        description: 'Destination contract or recipient address (e.g., 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)',
      },
      data: {
        type: 'string',
        description: 'Raw EVM bytecode calldata (optional, default: 0x)',
      },
      value: {
        type: 'string',
        description: 'Native ETH value in Wei to send (optional, default: 0)',
      },
      amountUsdc: {
        type: 'number',
        description: 'USDC token amount involved in transaction (for spending cap evaluation, e.g., 0.05)',
      },
    },
    required: ['to'],
  },
};

export async function handleExecuteSafeTxTool(
  client: FirewallClient,
  args: unknown
) {
  const parsed = ExecuteSafeTxInputSchema.parse(args);

  try {
    const result = await client.executeSafeTx({
      to: parsed.to,
      data: parsed.data,
      value: parsed.value,
      amountUsdc: parsed.amountUsdc,
    });

    if (!result.success) {
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: `[x402Firewall Security Block] Transaction rejected: ${result.reason}`,
          },
        ],
      };
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              success: true,
              to: parsed.to,
              amountUsdc: parsed.amountUsdc,
              signedTx: result.signedTx,
              txHash: result.txHash,
              simulation: result.simulation,
            },
            null,
            2
          ),
        },
      ],
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: `[x402Firewall Execution Error] ${message}`,
        },
      ],
    };
  }
}

