/**
 * What a connected dapp may ask for, decoded strictly. Everything a dapp
 * sends is untrusted: requests become ordinary proposals or message
 * signatures that the user approves like any other, and the destinations a
 * dapp names are marked as coming from untrusted content.
 */
import { isValidEvmAddress } from '@stackwallet/chains-evm';
import type { Account } from '@stackwallet/core-client';
import { z } from 'zod';

export const WC_METHODS = ['eth_sendTransaction', 'personal_sign', 'eth_signTypedData_v4'] as const;
export const WC_EVENTS = ['chainChanged', 'accountsChanged'] as const;

const Hex = z.string().regex(/^0x[0-9a-fA-F]*$/);
const Quantity = z
  .string()
  .regex(/^0x[0-9a-fA-F]{1,64}$/)
  .transform((h) => BigInt(h).toString());
const Address = z.string().refine(isValidEvmAddress, 'not an address');

const SendParams = z.tuple([
  z.object({
    from: Address,
    to: Address,
    value: Quantity.optional(),
    data: Hex.max(2 + 2 * 128 * 1024).optional(),
    input: Hex.max(2 + 2 * 128 * 1024).optional(),
  }),
]);
const PersonalParams = z.tuple([z.string().max(2 + 2 * 64 * 1024), Address]);
const TypedParams = z.tuple([
  Address,
  z.union([z.string().max(64 * 1024), z.record(z.string(), z.unknown())]),
]);

export type WcAction =
  | {
      kind: 'send';
      account: Account;
      to: string;
      /** Wei, decimal. */
      value: string;
      /** Empty for a plain transfer. */
      dataHex: string;
    }
  | { kind: 'sign'; account: Account; messageKind: 'personal' | 'typedData'; payload: string }
  | { kind: 'refuse'; code: number; message: string };

/** EIP-1193 error codes the dapp understands. */
export const USER_REJECTED = 4001;
export const UNAUTHORIZED = 4100;
export const UNSUPPORTED = 4200;
const INVALID_PARAMS = -32602;

function refuse(code: number, message: string): WcAction {
  return { kind: 'refuse', code, message };
}

function same(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

/**
 * `personal_sign` carries hex by convention. The core signs text, so bytes
 * that are not UTF-8 (usually a bare hash, which is blind signing) are refused.
 */
export function personalText(message: string): string | null {
  if (!/^0x([0-9a-fA-F]{2})*$/.test(message)) return message;
  const bytes = Uint8Array.from(message.slice(2).match(/../g) ?? [], (b) => parseInt(b, 16));
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Map one request to what StackWallet will do with it. `accounts` are the
 * session wallet's keyed EVM accounts; the request must name one of them on
 * the chain the dapp addressed.
 */
export function toAction(
  method: string,
  params: unknown,
  chainId: string,
  accounts: readonly Account[],
): WcAction {
  const onChain = accounts.filter((a) => a.chainId === chainId);
  const find = (address: string) => onChain.find((a) => same(a.address, address));
  if (onChain.length === 0) return refuse(UNAUTHORIZED, `no account on ${chainId}`);

  if (method === 'eth_sendTransaction') {
    const p = SendParams.safeParse(params);
    if (!p.success) return refuse(INVALID_PARAMS, 'invalid transaction');
    const tx = p.data[0];
    const account = find(tx.from);
    if (!account) return refuse(UNAUTHORIZED, 'unknown sender');
    const data = (tx.data ?? tx.input ?? '0x').slice(2);
    if (tx.data && tx.input && !same(tx.data, tx.input))
      return refuse(INVALID_PARAMS, 'data and input differ');
    return { kind: 'send', account, to: tx.to, value: tx.value ?? '0', dataHex: data };
  }
  if (method === 'personal_sign') {
    const p = PersonalParams.safeParse(params);
    if (!p.success) return refuse(INVALID_PARAMS, 'invalid message');
    const account = find(p.data[1]);
    if (!account) return refuse(UNAUTHORIZED, 'unknown signer');
    const text = personalText(p.data[0]);
    if (text === null) return refuse(UNSUPPORTED, 'refusing to sign bytes that are not text');
    return { kind: 'sign', account, messageKind: 'personal', payload: text };
  }
  if (method === 'eth_signTypedData_v4') {
    const p = TypedParams.safeParse(params);
    if (!p.success) return refuse(INVALID_PARAMS, 'invalid typed data');
    const account = find(p.data[0]);
    if (!account) return refuse(UNAUTHORIZED, 'unknown signer');
    const payload = typeof p.data[1] === 'string' ? p.data[1] : JSON.stringify(p.data[1]);
    return { kind: 'sign', account, messageKind: 'typedData', payload };
  }
  return refuse(UNSUPPORTED, `${method} is not supported`);
}

/**
 * The namespaces StackWallet offers a dapp: only signing testnets the wallet
 * has a keyed account on, only the methods above. Chains the dapp requires
 * but StackWallet cannot sign on make the proposal unanswerable.
 */
export function buildNamespaces(
  required: readonly string[],
  accounts: readonly Account[],
  signingChains: ReadonlySet<string>,
):
  | {
      ok: true;
      namespaces: {
        eip155: { chains: string[]; accounts: string[]; methods: string[]; events: string[] };
      };
    }
  | { ok: false; error: string } {
  const usable = accounts.filter(
    (a) => a.family === 'evm' && a.derivationPath && signingChains.has(a.chainId),
  );
  const chains = [...new Set(usable.map((a) => a.chainId))];
  const missing = required.filter((c) => !chains.includes(c));
  if (missing.length > 0)
    return {
      ok: false,
      error: `The dapp requires ${missing.join(', ')}, which this wallet cannot sign on`,
    };
  if (chains.length === 0)
    return { ok: false, error: 'This wallet has no account on an EVM testnet' };
  return {
    ok: true,
    namespaces: {
      eip155: {
        chains,
        accounts: usable.map((a) => `${a.chainId}:${a.address}`),
        methods: [...WC_METHODS],
        events: [...WC_EVENTS],
      },
    },
  };
}

/** Dapp-supplied names and URLs are shown, never trusted: plain printable text only. */
export function cleanText(s: unknown, max = 80): string {
  if (typeof s !== 'string') return '';
  return s.replace(/[^\x20-\x7e]/g, '').slice(0, max);
}
