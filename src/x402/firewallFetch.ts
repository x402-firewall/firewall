import { PolicyEngine, PolicyViolationError } from '../core/PolicyEngine.js';
import { SignerManager } from '../core/SignerManager.js';
import { parsePaymentRequirements, type PaymentRequirement } from './parser.js';
import { X402Facilitator, type FacilitatorConfig } from './facilitator.js';
import { logger } from '../utils/logger.js';

export interface FirewallFetchOptions {
  policyEngine: PolicyEngine;
  signerManager: SignerManager;
  facilitator?: X402Facilitator;
  facilitatorConfig?: FacilitatorConfig;
  throwOnViolation?: boolean;
}

export type FirewallFetchFn = (
  input: string | URL | Request,
  init?: RequestInit
) => Promise<Response>;

// Backwards compatibility aliases
export type GuardedFetchOptions = FirewallFetchOptions;
export type GuardedFetchFn = FirewallFetchFn;

/**
 * Creates a drop-in fetch replacement that automatically intercepts HTTP 402 responses,
 * validates payments against the PolicyEngine, signs the EIP-3009 payload, and retries.
 */
export function createFirewallFetch(options: FirewallFetchOptions): FirewallFetchFn {
  const {
    policyEngine,
    signerManager,
    throwOnViolation = true,
  } = options;

  const facilitator = options.facilitator || new X402Facilitator(options.facilitatorConfig);

  return async function firewallFetch(
    input: string | URL | Request,
    init?: RequestInit
  ): Promise<Response> {
    const urlString = typeof input === 'string'
      ? input
      : input instanceof URL
      ? input.toString()
      : input.url;

    // 1. Execute initial HTTP request (clone if input is Request to keep stream available for retry)
    const initialInput = input instanceof Request ? input.clone() : input;
    const response = await fetch(initialInput, init);

    // 2. If status is NOT 402, return response immediately
    if (response.status !== 402) {
      return response;
    }

    logger.info('Received HTTP 402 Payment Required; initiating x402 firewall evaluation', {
      url: urlString,
    });

    // 3. Parse payment requirement from response headers/body
    let requirement: PaymentRequirement;
    try {
      requirement = await parsePaymentRequirements(response);
    } catch (parseErr) {
      logger.error('Failed to parse x402 payment requirements from 402 response', {
        error: String(parseErr),
        url: urlString,
      });
      return response;
    }

    // 4. Extract domain from target URL for allowlist checking
    let domain: string | undefined;
    try {
      domain = new URL(urlString).hostname;
    } catch {
      // Fallback
    }

    // 5. Evaluate proposed payment with PolicyEngine
    const evaluation = policyEngine.evaluate({
      amountUsdc: requirement.maxAmountRequired,
      recipientAddress: requirement.payTo,
      domain,
    });

    if (!evaluation.allowed) {
      logger.warn('x402 payment BLOCKED by PolicyEngine firewall', {
        reason: evaluation.reason,
        amountUsdc: requirement.maxAmountRequired,
        payTo: requirement.payTo,
        url: urlString,
      });

      if (throwOnViolation) {
        throw new PolicyViolationError(
          evaluation.reason || 'Payment rejected by firewall policy',
          {
            amountUsdc: requirement.maxAmountRequired,
            recipientAddress: requirement.payTo,
            domain,
          }
        );
      }
      return response;
    }

    // 6. Sign EIP-3009 payment authorization payload
    const paymentPayload = await facilitator.createPaymentPayload(requirement, signerManager);
    const encodedPayment = facilitator.encodeHeader(paymentPayload);

    // 7. Record allowed spend in SQLite audit log
    policyEngine.recordAllowedSpend({
      amountUsdc: requirement.maxAmountRequired,
      recipient: requirement.payTo,
      domain,
    });

    // 8. Prepare retry request headers with X-PAYMENT
    const retryHeaders = new Headers(init?.headers);
    retryHeaders.set('X-PAYMENT', encodedPayment);
    retryHeaders.set('x-payment', encodedPayment);

    const retryInit: RequestInit = {
      ...init,
      headers: retryHeaders,
    };

    logger.info('Submitting signed x402 payment retry', {
      url: urlString,
      amountUsdc: requirement.maxAmountRequired,
      payTo: requirement.payTo,
    });

    // 9. Execute retry request with signed authorization header
    const retryInput = input instanceof Request ? input.clone() : input;
    return fetch(retryInput, retryInit);
  };
}

export const createGuardedFetch = createFirewallFetch;

