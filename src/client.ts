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

  /**
   * Returns the agent's derived public Ethereum address on Base L2.
   */
  public getAddress(): Address {
    return this.signerManager.getAddress();
  }

  /**
   * Queries the current budget caps, rolling 1h / 24h spends, and remaining USDC allowances.
   */
  public getBudgetStatus(): BudgetStatus {
    return this.policyEngine.getBudgetStatus();
  }

  /**
   * Retrieves recent permitted and blocked transactions from the local SQLite audit log.
   *
   * @param limit - Maximum number of records to retrieve (default: 20)
   * @param status - Optional filter for 'ALLOWED' or 'BLOCKED' entries
   */
  public getAuditLogs(
    limit: number = 20,
    status?: 'ALLOWED' | 'BLOCKED'
  ): AuditLogRecord[] {
    return this.spendTracker.getRecentLogs(limit, status ? { status } : undefined);
  }

  /**
   * Evaluates, simulates via eth_call, signs, and executes an on-chain EVM transaction
   * against strict spending caps and dangerous selector checks.
   *
   * @param params - Transaction parameters (to, calldata, value, amountUsdc)
   * @returns SafeTxResult containing success status, signed transaction hex, and simulation details
   */
  public async executeSafeTx(params: SafeTxParams): Promise<SafeTxResult> {
    return this.policyEngine.withLock(async () => {
      let amountUsdc = params.amountUsdc ?? 0;

      // Extract amount from calldata if calldata is a direct token transfer and caller provided 0 or omitted it
      if (params.data && params.data.length >= 138) {
        const inspection = this.evmSimulator.inspectCalldata(
          params.data,
          this.policyEngine.getPolicy().maxPerCallUsdc,
          this.policyEngine.getPolicy().blockUnlimitedApprovals
        );
        if (inspection.functionName === 'transfer' && inspection.decodedParams?.amountUsdc) {
          amountUsdc = Math.max(amountUsdc, inspection.decodedParams.amountUsdc);
        }
      }

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
        value: params.value ? BigInt(params.value) : 0n,
      } as Parameters<typeof this.signerManager.signTransaction>[0]);

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
    });
  }

  /**
   * Closes the local SQLite audit database connection.
   */
  public close(): void {
    this.spendTracker.close();
  }

  /**
   * Supports TypeScript 5.2+ explicit resource management (`using client = new FirewallClient()`).
   */
  public [Symbol.dispose](): void {
    this.close();
  }
}

// Backwards compatibility alias
export const GuardedClient = FirewallClient;
