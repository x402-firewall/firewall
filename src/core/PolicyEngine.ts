import type { Address } from 'viem';
import { KNOWN_BURN_ADDRESSES } from '../config/defaults.js';
import { type FirewallPolicy, createFirewallPolicy } from '../config/schema.js';
import { EvmSimulator } from './EvmSimulator.js';
import { SpendTracker } from './SpendTracker.js';
import { sendWebhookAlert } from '../utils/webhook.js';
import { logger } from '../utils/logger.js';

export interface EvaluationRequest {
  amountUsdc: number;
  recipientAddress?: Address | string;
  domain?: string;
  rawCalldata?: `0x${string}`;
  nativeValueWei?: bigint;
}

export interface PolicyEvaluationResult {
  allowed: boolean;
  reason?: string;
  currentHourlySpend: number;
  currentDailySpend: number;
  remainingHourlyAllowance: number;
  remainingDailyAllowance: number;
}

export interface BudgetStatus {
  maxPerCallUsdc: number;
  maxHourlyUsdc: number;
  maxDailyUsdc: number;
  currentHourlySpend: number;
  currentDailySpend: number;
  remainingHourlyAllowance: number;
  remainingDailyAllowance: number;
}

export class PolicyViolationError extends Error {
  public readonly reason: string;
  public readonly details: Partial<EvaluationRequest>;

  constructor(reason: string, details: Partial<EvaluationRequest> = {}) {
    super(`[x402Firewall Policy Violation] ${reason}`);
    this.name = 'PolicyViolationError';
    this.reason = reason;
    this.details = details;
  }
}

export class PolicyEngine {
  private policy: FirewallPolicy;
  private spendTracker: SpendTracker;
  private evmSimulator: EvmSimulator;

  constructor(
    policy?: Partial<FirewallPolicy>,
    spendTracker?: SpendTracker,
    evmSimulator?: EvmSimulator
  ) {
    this.policy = createFirewallPolicy(policy);
    this.spendTracker = spendTracker || new SpendTracker(this.policy.databasePath);
    this.evmSimulator = evmSimulator || new EvmSimulator(this.policy.network);
  }

  public getPolicy(): FirewallPolicy {
    return this.policy;
  }

  public getSpendTracker(): SpendTracker {
    return this.spendTracker;
  }

  public getBudgetStatus(): BudgetStatus {
    const currentHourlySpend = this.spendTracker.getHourlySpend();
    const currentDailySpend = this.spendTracker.getDailySpend();

    return {
      maxPerCallUsdc: this.policy.maxPerCallUsdc,
      maxHourlyUsdc: this.policy.maxHourlyUsdc,
      maxDailyUsdc: this.policy.maxDailyUsdc,
      currentHourlySpend,
      currentDailySpend,
      remainingHourlyAllowance: Math.max(0, this.policy.maxHourlyUsdc - currentHourlySpend),
      remainingDailyAllowance: Math.max(0, this.policy.maxDailyUsdc - currentDailySpend),
    };
  }

  /**
   * Deterministically evaluates a transaction or x402 payment against all security rules
   */
  public evaluate(req: EvaluationRequest): PolicyEvaluationResult {
    const { amountUsdc, recipientAddress, domain, rawCalldata, nativeValueWei } = req;
    const currentHourlySpend = this.spendTracker.getHourlySpend();
    const currentDailySpend = this.spendTracker.getDailySpend();

    const remainingHourlyAllowance = Math.max(0, this.policy.maxHourlyUsdc - currentHourlySpend);
    const remainingDailyAllowance = Math.max(0, this.policy.maxDailyUsdc - currentDailySpend);

    // Rule 0A: Positive finite amount check (prevents negative spend attacks & velocity reset exploits)
    if (!Number.isFinite(amountUsdc) || amountUsdc < 0) {
      const reason = `Policy violation: Invalid payment amount ($${amountUsdc} USDC). Amount must be a positive finite number`;
      return this.handleViolation(reason, req, currentHourlySpend, currentDailySpend);
    }

    // Rule 0B: Native ETH Value Transfer Drain Protection
    // x402 is an ERC-20 / USDC micro-payment standard. Uncontrolled native ETH transfers can drain funds.
    if (nativeValueWei && nativeValueWei > 0n) {
      const reason = `Policy violation: Unauthorized native ETH transfer blocked (${nativeValueWei.toString()} Wei). Native value transfers are forbidden under USDC micro-payment guardrails`;
      return this.handleViolation(reason, req, currentHourlySpend, currentDailySpend);
    }

    // Rule 1: Per-call limit check
    if (amountUsdc > this.policy.maxPerCallUsdc) {
      const reason = `Per-call spend limit exceeded: requested $${amountUsdc.toFixed(4)} USDC > limit of $${this.policy.maxPerCallUsdc.toFixed(4)} USDC`;
      return this.handleViolation(reason, req, currentHourlySpend, currentDailySpend);
    }

    // Rule 2: Hourly velocity limit check
    if (currentHourlySpend + amountUsdc > this.policy.maxHourlyUsdc) {
      const reason = `Hourly spend limit exceeded: requesting $${amountUsdc.toFixed(4)} USDC + current spend $${currentHourlySpend.toFixed(4)} USDC > limit of $${this.policy.maxHourlyUsdc.toFixed(4)} USDC (remaining: $${remainingHourlyAllowance.toFixed(4)} USDC)`;
      return this.handleViolation(reason, req, currentHourlySpend, currentDailySpend);
    }

    // Rule 3: Daily velocity limit check
    if (currentDailySpend + amountUsdc > this.policy.maxDailyUsdc) {
      const reason = `Daily spend limit exceeded: requesting $${amountUsdc.toFixed(4)} USDC + current spend $${currentDailySpend.toFixed(4)} USDC > limit of $${this.policy.maxDailyUsdc.toFixed(4)} USDC (remaining: $${remainingDailyAllowance.toFixed(4)} USDC)`;
      return this.handleViolation(reason, req, currentHourlySpend, currentDailySpend);
    }

    // Rule 4: Domain allowlist check
    if (this.policy.allowedDomains.length > 0) {
      if (!domain) {
        const reason = 'Policy violation: Domain must be specified when allowedDomains allowlist is active';
        return this.handleViolation(reason, req, currentHourlySpend, currentDailySpend);
      }

      const normalizedDomain = this.normalizeDomain(domain);
      const isAllowed = this.policy.allowedDomains.some((pattern) =>
        this.matchDomain(normalizedDomain, pattern.toLowerCase())
      );

      if (!isAllowed) {
        const reason = `Policy violation: Domain '${normalizedDomain}' is not in allowedDomains list`;
        return this.handleViolation(reason, req, currentHourlySpend, currentDailySpend);
      }
    }

    // Rule 5: Recipient check (burn addresses + allowedContracts check)
    if (recipientAddress) {
      const normalizedRecipient = recipientAddress.toLowerCase() as Address;

      if (KNOWN_BURN_ADDRESSES.includes(normalizedRecipient)) {
        const reason = `Policy violation: Recipient '${recipientAddress}' is a known zero/burn address`;
        return this.handleViolation(reason, req, currentHourlySpend, currentDailySpend);
      }

      if (this.policy.allowedContracts.length > 0) {
        const isAllowedContract = this.policy.allowedContracts.some(
          (contract) => contract.toLowerCase() === normalizedRecipient
        );

        if (!isAllowedContract) {
          const reason = `Policy violation: Recipient address '${recipientAddress}' is not in allowedContracts list`;
          return this.handleViolation(reason, req, currentHourlySpend, currentDailySpend);
        }
      }
    }

    // Rule 6: Calldata inspection for dangerous selectors (approvals, drains, transferFrom)
    if (rawCalldata && rawCalldata !== '0x') {
      const inspection = this.evmSimulator.inspectCalldata(
        rawCalldata,
        this.policy.maxPerCallUsdc,
        this.policy.blockUnlimitedApprovals
      );

      if (!inspection.isSafe) {
        const reason = inspection.reason || 'Policy violation: Calldata failed security inspection';
        return this.handleViolation(reason, req, currentHourlySpend, currentDailySpend);
      }
    }

    // All rules passed
    return {
      allowed: true,
      currentHourlySpend,
      currentDailySpend,
      remainingHourlyAllowance,
      remainingDailyAllowance,
    };
  }

  /**
   * Helper to evaluate and throw PolicyViolationError if violation occurs
   */
  public evaluateOrThrow(req: EvaluationRequest): PolicyEvaluationResult {
    const result = this.evaluate(req);
    if (!result.allowed) {
      throw new PolicyViolationError(result.reason || 'Policy check failed', req);
    }
    return result;
  }

  public recordAllowedSpend(params: {
    amountUsdc: number;
    recipient?: string;
    domain?: string;
    txHash?: string;
    timestamp?: number;
  }) {
    return this.spendTracker.recordSpend(params);
  }

  private handleViolation(
    reason: string,
    req: EvaluationRequest,
    currentHourlySpend: number,
    currentDailySpend: number
  ): PolicyEvaluationResult {
    // 1. Record BLOCKED entry in SpendTracker
    this.spendTracker.recordBlocked({
      amountUsdc: req.amountUsdc,
      recipient: req.recipientAddress,
      domain: req.domain,
      reason,
      calldata: req.rawCalldata,
    });

    // 2. Dispatch webhook alert asynchronously without blocking caller
    if (this.policy.alertWebhookUrl) {
      sendWebhookAlert(this.policy.alertWebhookUrl, {
        event: 'POLICY_VIOLATION',
        reason,
        amountUsdc: req.amountUsdc,
        recipient: req.recipientAddress,
        domain: req.domain,
        calldata: req.rawCalldata,
        timestamp: new Date().toISOString(),
      }).catch((err) => {
        logger.warn('Failed to send webhook alert', { error: String(err) });
      });
    }

    return {
      allowed: false,
      reason,
      currentHourlySpend,
      currentDailySpend,
      remainingHourlyAllowance: Math.max(0, this.policy.maxHourlyUsdc - currentHourlySpend),
      remainingDailyAllowance: Math.max(0, this.policy.maxDailyUsdc - currentDailySpend),
    };
  }

  private normalizeDomain(input: string): string {
    let clean = input.trim().toLowerCase();
    try {
      const url = clean.includes('://') ? new URL(clean) : new URL(`http://${clean}`);
      return url.hostname;
    } catch {
      return clean.split('/')[0].split(':')[0];
    }
  }

  private matchDomain(domain: string, pattern: string): boolean {
    if (pattern === domain) return true;
    if (pattern.startsWith('*.')) {
      const root = pattern.slice(2);
      return domain === root || domain.endsWith('.' + root);
    }
    return false;
  }
}
