import {
  type Address,
  createPublicClient,
  http,
  maxUint256,
  slice,
  hexToBigInt,
} from 'viem';
import { base, baseSepolia } from 'viem/chains';
import { DANGEROUS_SELECTORS, USDC_DECIMALS } from '../config/defaults.js';
import type { Network } from '../config/schema.js';
import { logger } from '../utils/logger.js';

export interface CalldataInspectionResult {
  isSafe: boolean;
  reason?: string;
  selector?: string;
  functionName?: string;
  decodedParams?: {
    spender?: Address;
    recipient?: Address;
    amountRaw?: bigint;
    amountUsdc?: number;
    isUnlimited?: boolean;
  };
}

export interface SimulationResult {
  success: boolean;
  error?: string;
  returnData?: string;
  gasUsed?: bigint;
}

export interface MinimalEvmClient {
  call: (args: {
    to: Address;
    data?: `0x${string}`;
    value?: bigint;
    account?: Address;
  }) => Promise<{ data?: `0x${string}` }>;
}

export class EvmSimulator {
  private client?: MinimalEvmClient;
  private network: Network;

  constructor(network: Network = 'base-sepolia', rpcUrl?: string, customClient?: MinimalEvmClient) {
    this.network = network;
    if (customClient) {
      this.client = customClient;
    } else if (rpcUrl) {
      const chain = network === 'base' ? base : baseSepolia;
      this.client = createPublicClient({
        chain,
        transport: http(rpcUrl),
      });
    }
  }

  /**
   * Deterministically inspects raw calldata for dangerous or malicious signatures/parameters
   */
  public inspectCalldata(
    data?: `0x${string}`,
    maxPerCallUsdc: number = 0.05,
    blockUnlimitedApprovals: boolean = true
  ): CalldataInspectionResult {
    if (!data || data === '0x' || data.length < 10) {
      return { isSafe: true };
    }

    const selector = slice(data, 0, 4).toLowerCase();

    // 1. ERC-20 approve(address spender, uint256 amount) - selector 0x095ea7b3
    if (selector === DANGEROUS_SELECTORS.APPROVE) {
      if (data.length < 138) {
        return {
          isSafe: false,
          reason: 'Malformed ERC-20 approve calldata (insufficient length)',
          selector,
          functionName: 'approve',
        };
      }

      const spender = slice(data, 16, 36).toLowerCase() as Address;
      const amountRaw = hexToBigInt(slice(data, 36, 68));
      const isUnlimited = amountRaw === maxUint256 || amountRaw >= (maxUint256 / 2n);
      const amountUsdc = Number(amountRaw) / 10 ** USDC_DECIMALS;

      const maxAllowedRaw = BigInt(Math.floor(maxPerCallUsdc * 10 ** USDC_DECIMALS));

      if (blockUnlimitedApprovals && (isUnlimited || amountRaw > maxAllowedRaw)) {
        return {
          isSafe: false,
          reason: `Policy violation: Unlimited or excessive token approval detected (${isUnlimited ? 'MAX_UINT256' : `${amountUsdc} USDC`} > cap of ${maxPerCallUsdc} USDC)`,
          selector,
          functionName: 'approve',
          decodedParams: {
            spender,
            amountRaw,
            amountUsdc,
            isUnlimited,
          },
        };
      }

      return {
        isSafe: true,
        selector,
        functionName: 'approve',
        decodedParams: {
          spender,
          amountRaw,
          amountUsdc,
          isUnlimited: false,
        },
      };
    }

    // 2. ERC-20 increaseAllowance(address spender, uint256 addedValue) - selector 0x39509351
    if (selector === DANGEROUS_SELECTORS.INCREASE_ALLOWANCE) {
      if (data.length < 138) {
        return {
          isSafe: false,
          reason: 'Malformed ERC-20 increaseAllowance calldata',
          selector,
          functionName: 'increaseAllowance',
        };
      }

      const spender = slice(data, 16, 36).toLowerCase() as Address;
      const amountRaw = hexToBigInt(slice(data, 36, 68));
      const maxAllowedRaw = BigInt(Math.floor(maxPerCallUsdc * 10 ** USDC_DECIMALS));

      if (blockUnlimitedApprovals && (amountRaw === maxUint256 || amountRaw > maxAllowedRaw)) {
        return {
          isSafe: false,
          reason: `Policy violation: Unlimited or excessive allowance increase detected via increaseAllowance (0x39509351)`,
          selector,
          functionName: 'increaseAllowance',
          decodedParams: {
            spender,
            amountRaw,
          },
        };
      }
    }

    // 3. ERC-721 / ERC-1155 setApprovalForAll(address operator, bool approved) - selector 0xa22cb465
    if (selector === DANGEROUS_SELECTORS.SET_APPROVAL_FOR_ALL) {
      return {
        isSafe: false,
        reason: 'Policy violation: Blocked dangerous setApprovalForAll selector (0xa22cb465) commonly used in wallet drainers',
        selector,
        functionName: 'setApprovalForAll',
      };
    }

    // 4. EIP-2612 permit(...) - selector 0xd505accf
    if (selector === DANGEROUS_SELECTORS.PERMIT) {
      return {
        isSafe: false,
        reason: 'Policy violation: Blocked raw permit selector (0xd505accf); use standard x402 EIP-3009 transfer authorizations',
        selector,
        functionName: 'permit',
      };
    }

    // 5. Dangerous NFT / Token Drainer Selector: safeTransferFrom (0x42842e0e)
    if (selector === DANGEROUS_SELECTORS.SAFE_TRANSFER_FROM_ERC721) {
      return {
        isSafe: false,
        reason: 'Policy violation: Blocked dangerous ERC-721 safeTransferFrom selector (0x42842e0e)',
        selector,
        functionName: 'safeTransferFrom',
      };
    }

    // 6. transferFrom (0x23b872dd)
    if (selector === DANGEROUS_SELECTORS.TRANSFER_FROM) {
      return {
        isSafe: false,
        reason: 'Policy violation: Blocked unauthorized transferFrom selector (0x23b872dd)',
        selector,
        functionName: 'transferFrom',
      };
    }

    // 7. ERC-1155 safeTransferFrom (0xb88d4fde)
    if (selector === DANGEROUS_SELECTORS.SAFE_TRANSFER_FROM_ERC1155) {
      return {
        isSafe: false,
        reason: 'Policy violation: Blocked dangerous ERC-1155 safeTransferFrom selector (0xb88d4fde)',
        selector,
        functionName: 'safeTransferFrom',
      };
    }

    // 8. ERC-20 transfer(address to, uint256 amount) - selector 0xa9059cbb
    if (selector === DANGEROUS_SELECTORS.TRANSFER) {
      if (data.length < 138) {
        return {
          isSafe: false,
          reason: 'Malformed ERC-20 transfer calldata (insufficient length)',
          selector,
          functionName: 'transfer',
        };
      }

      const recipient = slice(data, 16, 36).toLowerCase() as Address;
      const amountRaw = hexToBigInt(slice(data, 36, 68));
      const amountUsdc = Number(amountRaw) / 10 ** USDC_DECIMALS;
      const maxAllowedRaw = BigInt(Math.floor(maxPerCallUsdc * 10 ** USDC_DECIMALS));

      if (amountRaw > maxAllowedRaw) {
        return {
          isSafe: false,
          reason: `Policy violation: Transfer amount of ${amountUsdc} USDC exceeds per-call cap of ${maxPerCallUsdc} USDC`,
          selector,
          functionName: 'transfer',
          decodedParams: {
            recipient,
            amountRaw,
            amountUsdc,
            isUnlimited: false,
          },
        };
      }

      return {
        isSafe: true,
        selector,
        functionName: 'transfer',
        decodedParams: {
          recipient,
          amountRaw,
          amountUsdc,
          isUnlimited: false,
        },
      };
    }

    return {
      isSafe: true,
      selector,
    };
  }

  /**
   * Runs an off-chain eth_call simulation via viem
   */
  public async simulateTx(tx: {
    to: Address;
    data?: `0x${string}`;
    value?: bigint;
    account?: Address;
  }): Promise<SimulationResult> {
    if (!this.client) {
      logger.debug('No RPC client configured for EVM simulation; static inspection passed');
      return { success: true };
    }

    try {
      const response = await this.client.call({
        to: tx.to,
        data: tx.data,
        value: tx.value,
        account: tx.account,
      });

      return {
        success: true,
        returnData: response.data,
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.warn('EVM simulation failed or reverted', { error: message, to: tx.to });
      return {
        success: false,
        error: message,
      };
    }
  }
}
