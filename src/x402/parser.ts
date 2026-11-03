import { z } from 'zod';
import type { Address } from 'viem';
import { AddressSchema, NetworkSchema, type Network } from '../config/schema.js';
import { USDC_ADDRESSES, USDC_DECIMALS } from '../config/defaults.js';
import { logger } from '../utils/logger.js';

export interface PaymentRequirement {
  scheme: string;
  network: Network;
  payTo: Address;
  asset: string;
  maxAmountRequired: number; // In USDC units, e.g. 0.05
  atomicAmount: bigint;      // In 6-decimal units, e.g. 50000n
  resource?: string;
  description?: string;
  validBefore?: number;
  extra?: Record<string, unknown>;
}

const RawPaymentRequirementSchema = z.object({
  scheme: z.string().default('exact'),
  network: NetworkSchema.default('base-sepolia'),
  payTo: AddressSchema,
  asset: z.string().default('USDC'),
  maxAmountRequired: z.union([z.number(), z.string()]).optional(),
  amount: z.union([z.number(), z.string()]).optional(),
  atomicAmount: z.union([z.string(), z.number(), z.bigint()]).optional(),
  resource: z.string().optional(),
  description: z.string().optional(),
  validBefore: z.number().int().positive().optional(),
});

/**
 * Normalizes payment amount from various representations (decimal USDC vs atomic units)
 */
function normalizeAmount(data: z.infer<typeof RawPaymentRequirementSchema>): {
  usdcAmount: number;
  atomicAmount: bigint;
} {
  // If atomicAmount is explicitly provided (e.g., 50000)
  if (data.atomicAmount !== undefined) {
    const atomic = BigInt(data.atomicAmount.toString());
    if (atomic < 0n) {
      throw new Error(`Invalid atomic payment amount: ${atomic}`);
    }
    const usdc = Number(atomic) / 10 ** USDC_DECIMALS;
    return { usdcAmount: usdc, atomicAmount: atomic };
  }

  // If maxAmountRequired or amount is specified
  const rawVal = data.maxAmountRequired ?? data.amount;
  if (rawVal === undefined) {
    throw new Error('x402 requirement missing payment amount (maxAmountRequired or amount)');
  }

  const numVal = typeof rawVal === 'string' ? parseFloat(rawVal) : rawVal;
  if (!Number.isFinite(numVal) || numVal < 0 || numVal > 1_000_000) {
    throw new Error(`Invalid payment amount: ${rawVal} (must be a positive number <= 1,000,000 USDC)`);
  }

  // Standard x402 specification uses decimal dollar amounts in maxAmountRequired (e.g., 0.05)
  const atomic = BigInt(Math.round(numVal * 10 ** USDC_DECIMALS));
  return { usdcAmount: numVal, atomicAmount: atomic };
}

/**
 * Parses PaymentRequirement from HTTP 402 response headers or body
 */
export async function parsePaymentRequirements(response: Response): Promise<PaymentRequirement> {
  let parsedRaw: Record<string, unknown> | null = null;

  // 1. Try parsing from X-PAYMENT-REQUIRED header
  const header =
    response.headers.get('x-payment-required') ||
    response.headers.get('X-Payment-Required') ||
    response.headers.get('X-PAYMENT-REQUIRED');

  if (header) {
    try {
      // Could be raw JSON or base64 JSON
      const decoded = header.startsWith('{')
        ? header
        : Buffer.from(header, 'base64').toString('utf-8');
      parsedRaw = JSON.parse(decoded);
    } catch (err) {
      logger.debug('Failed to parse X-Payment-Required header, falling back to body', {
        header,
        error: String(err),
      });
    }
  }

  // 2. If not found in headers, attempt to parse JSON body
  if (!parsedRaw) {
    try {
      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength, 10) > 1_000_000) {
        throw new Error('402 response body exceeds 1MB limit');
      }

      const cloned = response.clone();
      const bodyText = await cloned.text();
      if (bodyText.length > 1_000_000) {
        throw new Error('402 response body text exceeds 1MB limit');
      }

      const bodyJson = JSON.parse(bodyText) as Record<string, unknown>;

      if (bodyJson && typeof bodyJson === 'object') {
        parsedRaw =
          (bodyJson.paymentRequirements as Record<string, unknown>) ||
          (bodyJson.payment_requirements as Record<string, unknown>) ||
          (bodyJson.x402 as Record<string, unknown>) ||
          bodyJson;
      }
    } catch {
      // Body may not be JSON
    }
  }

  if (!parsedRaw) {
    throw new Error('Unable to extract x402 payment requirements from 402 response');
  }

  const validated = RawPaymentRequirementSchema.parse(parsedRaw);
  const { usdcAmount, atomicAmount } = normalizeAmount(validated);

  // Defensively strip any prototype pollution vectors from extra
  const safeExtra: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(validated)) {
    if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
      safeExtra[key] = val;
    }
  }

  return {
    scheme: validated.scheme,
    network: validated.network,
    payTo: validated.payTo,
    asset: validated.asset,
    maxAmountRequired: usdcAmount,
    atomicAmount,
    resource: validated.resource,
    description: validated.description,
    validBefore: validated.validBefore,
    extra: safeExtra,
  };
}
