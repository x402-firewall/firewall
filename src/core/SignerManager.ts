import {
  type PrivateKeyAccount,
  type Address,
  type Hex,
  bytesToHex,
  hexToSignature,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { CHAIN_IDS, USDC_ADDRESSES } from '../config/defaults.js';
import type { Network } from '../config/schema.js';
import { logger } from '../utils/logger.js';
import crypto from 'node:crypto';

export interface SignX402PaymentParams {
  to: Address;
  value: bigint;
  validAfter?: number;
  validBefore?: number;
  nonce?: Hex;
  network?: Network;
  usdcAddress?: Address;
}

export interface SignedPaymentPayload {
  from: Address;
  to: Address;
  value: string;
  validAfter: number;
  validBefore: number;
  nonce: Hex;
  v: number;
  r: Hex;
  s: Hex;
  signature: Hex;
}

export class SignerManager {
  // Use private symbol to prevent reflection / Object.keys / JSON leakage
  #account: PrivateKeyAccount;
  #network: Network;

  constructor(privateKey?: Hex, network: Network = 'base-sepolia') {
    this.#network = network;
    const isEphemeral = !privateKey;
    const key = privateKey || generatePrivateKey();
    this.#account = privateKeyToAccount(key);

    if (isEphemeral) {
      logger.warn(
        `No PRIVATE_KEY provided; generated ephemeral wallet ${this.#account.address} (funds deposited here will not persist across restarts)`
      );
    }
  }

  public getAddress(): Address {
    return this.#account.address;
  }

  public getNetwork(): Network {
    return this.#network;
  }

  /**
   * Signs EIP-712 / EIP-3009 transferWithAuthorization for native USDC on Base
   */
  public async signX402Payment(params: SignX402PaymentParams): Promise<SignedPaymentPayload> {
    if (params.network && params.network !== this.#network) {
      throw new Error(`Security violation: Payment network '${params.network}' does not match signer network '${this.#network}'`);
    }
    const network = this.#network;
    const chainId = CHAIN_IDS[network];
    const verifyingContract = params.usdcAddress || USDC_ADDRESSES[network];

    const nowSeconds = Math.floor(Date.now() / 1000);
    const validAfter = params.validAfter ?? 0;
    // Security Guard: Defensively clamp validity to at most 24 hours to prevent unbounded authorizations
    const maxAllowedValidBefore = nowSeconds + 86400;
    const requestedValidBefore = params.validBefore ?? (nowSeconds + 3600); // 1 hour validity default
    const validBefore = Math.max(nowSeconds + 60, Math.min(requestedValidBefore, maxAllowedValidBefore));

    if (validAfter >= validBefore) {
      throw new Error('Security violation: validAfter must be strictly less than validBefore');
    }

    const nonce = params.nonce ?? (bytesToHex(crypto.randomBytes(32)) as Hex);

    const domain = {
      name: 'USD Coin',
      version: '2',
      chainId,
      verifyingContract,
    } as const;

    const types = {
      TransferWithAuthorization: [
        { name: 'from', type: 'address' },
        { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' },
        { name: 'nonce', type: 'bytes32' },
      ],
    } as const;

    const message = {
      from: this.#account.address,
      to: params.to,
      value: params.value,
      validAfter: BigInt(validAfter),
      validBefore: BigInt(validBefore),
      nonce,
    };

    const signature = await this.#account.signTypedData({
      domain,
      types,
      primaryType: 'TransferWithAuthorization',
      message,
    });

    const { v, r, s } = hexToSignature(signature);

    return {
      from: this.#account.address,
      to: params.to,
      value: params.value.toString(),
      validAfter,
      validBefore,
      nonce,
      v: Number(v),
      r,
      s,
      signature,
    };
  }

  /**
   * Signs a raw message
   */
  public async signMessage(message: string): Promise<Hex> {
    return this.#account.signMessage({ message });
  }

  /**
   * Signs a typed data structure
   */
  public async signTypedData(
    parameters: Parameters<PrivateKeyAccount['signTypedData']>[0]
  ): Promise<Hex> {
    return this.#account.signTypedData(parameters);
  }

  /**
   * Signs an EVM transaction
   */
  public async signTransaction(
    tx: Parameters<PrivateKeyAccount['signTransaction']>[0]
  ): Promise<Hex> {
    const chainId: number = ((tx as any)?.chainId as number | undefined) ?? CHAIN_IDS[this.#network];
    const fullTx: any = {
      type: 'eip1559',
      maxFeePerGas: 1000000000n,
      maxPriorityFeePerGas: 10000000n,
      gas: 21000n,
      nonce: 0,
      ...tx,
      chainId,
      value: (tx as any)?.value !== undefined ? BigInt((tx as any).value) : 0n,
      data: (tx as any)?.data ?? '0x',
    };
    return this.#account.signTransaction(fullTx);
  }

  // --- Strict anti-leak protection ---
  public toJSON(): Record<string, unknown> {
    return {
      address: this.#account.address,
      network: this.#network,
    };
  }

  public toString(): string {
    return `[SignerManager: ${this.#account.address} (${this.#network})]`;
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}
