import type { Address } from 'viem';
import type { SignerManager, SignedPaymentPayload } from '../core/SignerManager.js';
import type { PaymentRequirement } from './parser.js';
import { logger } from '../utils/logger.js';
import { isSafeExternalUrl } from '../utils/webhook.js';

export interface FacilitatorConfig {
  mode?: 'local' | 'cloud';
  feeBps?: number; // Basis points (e.g., 5 = 0.05%)
  feeRecipient?: Address;
  cloudApiKey?: string;
  cloudDashboardUrl?: string;
}

export interface X402PaymentPayload {
  x402Version: string;
  scheme: string;
  network: string;
  payload: {
    authorization: SignedPaymentPayload;
    signature: `0x${string}`;
  };
  facilitator?: {
    feeBps: number;
    feeAmount: string;
    feeRecipient?: Address;
  };
}

export class X402Facilitator {
  private config: FacilitatorConfig;

  constructor(config?: FacilitatorConfig) {
    const rawCloudUrl = config?.cloudDashboardUrl || process.env.X402FIREWALL_CLOUD_URL || process.env.X402GUARD_CLOUD_URL || 'https://api.x402firewall.com';
    if (rawCloudUrl && !isSafeExternalUrl(rawCloudUrl)) {
      throw new Error(`Security violation: cloudDashboardUrl points to unsafe or internal address: ${rawCloudUrl}`);
    }

    this.config = {
      mode: config?.mode || (process.env.X402FIREWALL_CLOUD_API_KEY || process.env.X402GUARD_CLOUD_API_KEY ? 'cloud' : 'local'),
      feeBps: config?.feeBps ?? 0,
      feeRecipient: config?.feeRecipient,
      cloudApiKey: config?.cloudApiKey || process.env.X402FIREWALL_CLOUD_API_KEY || process.env.X402GUARD_CLOUD_API_KEY,
      cloudDashboardUrl: rawCloudUrl,
    };
  }

  public getConfig(): FacilitatorConfig {
    const { cloudApiKey, ...rest } = this.config;
    return {
      ...rest,
      cloudApiKey: cloudApiKey ? '***REDACTED***' : undefined,
    };
  }

  /**
   * Generates a signed x402 payment payload using EIP-3009 transferWithAuthorization
   */
  public async createPaymentPayload(
    req: PaymentRequirement,
    signer: SignerManager
  ): Promise<X402PaymentPayload> {
    if (req.network !== signer.getNetwork()) {
      throw new Error(
        `Security violation: x402 payment requested network '${req.network}' does not match client signer network '${signer.getNetwork()}'`
      );
    }

    const signedAuth = await signer.signX402Payment({
      to: req.payTo,
      value: req.atomicAmount,
      network: req.network,
      validBefore: req.validBefore,
    });

    const feeBps = this.config.feeBps ?? 0;
    const feeAmount = feeBps > 0 ? (req.atomicAmount * BigInt(feeBps) / 10000n).toString() : '0';

    const payload: X402PaymentPayload = {
      x402Version: '0.1',
      scheme: req.scheme || 'exact',
      network: req.network,
      payload: {
        authorization: signedAuth,
        signature: signedAuth.signature,
      },
    };

    if (feeBps > 0 && this.config.feeRecipient) {
      payload.facilitator = {
        feeBps,
        feeAmount,
        feeRecipient: this.config.feeRecipient,
      };
    }

    // In hosted cloud mode, send audit log to cloud endpoint asynchronously
    if (this.config.mode === 'cloud' && this.config.cloudApiKey) {
      this.reportCloudAudit({
        event: 'PAYMENT_SIGNED',
        sender: signer.getAddress(),
        recipient: req.payTo,
        amountUsdc: req.maxAmountRequired,
        network: req.network,
        timestamp: new Date().toISOString(),
      }).catch((err) => {
        logger.debug('Failed to report payment to x402Firewall cloud dashboard', { error: String(err) });
      });
    }

    return payload;
  }

  /**
   * Encodes a payment payload into a Base64 string for the X-PAYMENT HTTP header
   */
  public encodeHeader(payload: X402PaymentPayload): string {
    return Buffer.from(JSON.stringify(payload)).toString('base64');
  }

  /**
   * Decodes a Base64 or JSON X-PAYMENT HTTP header
   */
  public decodeHeader(headerValue: string): X402PaymentPayload {
    const raw = headerValue.startsWith('{')
      ? headerValue
      : Buffer.from(headerValue, 'base64').toString('utf-8');
    return JSON.parse(raw) as X402PaymentPayload;
  }

  private async reportCloudAudit(data: Record<string, unknown>): Promise<void> {
    if (!this.config.cloudApiKey || !this.config.cloudDashboardUrl) return;

    try {
      await fetch(`${this.config.cloudDashboardUrl}/v1/audit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.cloudApiKey}`,
        },
        body: JSON.stringify(data),
        signal: AbortSignal.timeout(3000),
      });
    } catch {
      // Non-blocking
    }
  }
}

