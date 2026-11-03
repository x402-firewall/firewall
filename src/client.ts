import type { Hex, Address } from 'viem';
import { type FirewallPolicy, createFirewallPolicy, loadPolicyFromEnv } from './config/schema.js';
import { PolicyEngine, type BudgetStatus } from './core/PolicyEngine.js';
import { SpendTracker, type AuditLogRecord } from './core/SpendTracker.js';
import { EvmSimulator, type SimulationResult } from './core/EvmSimulator.js';
import { SignerManager } from './core/SignerManager.js';
import { X402Facilitator, type FacilitatorConfig } from './x402/facilitator.js';
import { createFirewallFetch, type FirewallFetchFn } from './x402/firewallFetch.js';
import { logger } from './utils/logger.js';

export interface FirewallClientOptions {
  policy?: Partial<FirewallPolicy>;
  privateKey?: Hex;
  rpcUrl?: string;
  facilitatorConfig?: FacilitatorConfig;
  spendTracker?: SpendTracker;
  throwOnViolation?: boolean;
}

export type GuardedClientOptions = FirewallClientOptions;

export interface SafeTxParams {
  to: Address;
  data?: `0x${string}`;
  value?: bigint;
  amountUsdc?: number;
}

export interface SafeTxResult {
  success: boolean;
  txHash?: Hex;
  signedTx?: Hex;
  reason?: string;
  simulation?: SimulationResult;
}

export class FirewallClient {
  public readonly policyEngine: PolicyEngine;
  public readonly signerManager: SignerManager;
  public readonly spendTracker: SpendTracker;
  public readonly evmSimulator: EvmSimulator;
  public readonly facilitator: X402Facilitator;
  public readonly fetch: FirewallFetchFn;

  constructor(options: FirewallClientOptions = {}) {
    const policy = options.policy
      ? createFirewallPolicy(options.policy)
      : loadPolicyFromEnv();

    this.spendTracker = options.spendTracker || new SpendTracker(policy.databasePath);
    this.evmSimulator = new EvmSimulator(policy.network, options.rpcUrl);
    this.policyEngine = new PolicyEngine(policy, this.spendTracker, this.evmSimulator);

    const privateKey = options.privateKey || (process.env.PRIVATE_KEY as Hex | undefined);
    this.signerManager = new SignerManager(privateKey, policy.network);

    this.facilitator = new X402Facilitator(options.facilitatorConfig);

    this.fetch = createFirewallFetch({
      policyEngine: this.policyEngine,
      signerManager: this.signerManager,
      facilitator: this.facilitator,
      throwOnViolation: options.throwOnViolation ?? true,
    });
  }

  public getAddress(): Address {
    return this.signerManager.getAddress();
  }

  public getBudgetStatus(): BudgetStatus {
    return this.policyEngine.getBudgetStatus();
  }

  public getAuditLogs(
    limit: number = 20,
    status?: 'ALLOWED' | 'BLOCKED'
  ): AuditLogRecord[] {
    return this.spendTracker.getRecentLogs(limit, status ? { status } : undefined);
  }

  public async executeSafeTx(params: SafeTxParams): Promise<SafeTxResult> {
    const amountUsdc = params.amountUsdc ?? 0;

    // 1. Policy Evaluation
    const evalResult = this.policyEngine.evaluate({
      amountUsdc,
      recipientAddress: params.to,
      rawCalldata: params.data,
      nativeValueWei: params.value,
    });

    if (!evalResult.allowed) {
      logger.warn('Safe transaction rejected by PolicyEngine firewall', {
        reason: evalResult.reason,
        to: params.to,
      });
      return {
        success: false,
        reason: evalResult.reason,
      };
    }

    // 2. Pre-execution Simulation via EVM Simulator
    const simResult = await this.evmSimulator.simulateTx({
      to: params.to,
      data: params.data,
      value: params.value,
      account: this.signerManager.getAddress(),
    });

    if (!simResult.success) {
      this.spendTracker.recordBlocked({
        amountUsdc,
        recipient: params.to,
        reason: `Simulation reverted: ${simResult.error}`,
        calldata: params.data,
      });
      return {
        success: false,
        reason: `Transaction simulation failed: ${simResult.error}`,
        simulation: simResult,
      };
    }

    // 3. Sign Transaction
    const signedTx = await this.signerManager.signTransaction({
      to: params.to,
      data: params.data,
      value: params.value,
      chainId: undefined,
    } as any);

    // 4. Record spend in tracker
    this.policyEngine.recordAllowedSpend({
      amountUsdc,
      recipient: params.to,
      txHash: signedTx,
    });

    return {
      success: true,
      signedTx,
      txHash: signedTx,
      simulation: simResult,
    };
  }

  public close(): void {
    this.spendTracker.close();
  }
}

// Backwards compatibility alias
export const GuardedClient = FirewallClient;
