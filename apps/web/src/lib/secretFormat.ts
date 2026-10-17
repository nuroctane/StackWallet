import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { base32, base58, base64, bech32, createBase58check } from '@scure/base';
import type { ChainInfo } from '@stackwallet/chains';

const b58check = createBase58check(sha256);

/**
 * A raw private key from the core in the import format each family's other
 * wallets expect. The core already hands over the family's own key (Stark
 * key, Chia BLS scalar, Waves Curve25519, Mixin seed, Qubic subseed), so this
 * only wraps bytes; families whose wallets import phrases rather than keys
 * get plain hex and say so in `privateKeyFormat`.
 */
export function formatPrivateKey(chain: ChainInfo, secretHex: string, publicHex: string): string {
  const secret = () => hexToBytes(secretHex);
  const keypair = () => {
    const kp = new Uint8Array(64);
    kp.set(secret(), 0);
    kp.set(hexToBytes(publicHex), 32);
    return kp;
  };
  switch (chain.family) {
    case 'evm':
    case 'hyperliquid':
    case 'vechain':
    case 'fuel':
    case 'chromia':
    case 'gala':
    case 'starknet':
    case 'starcoin':
    case 'substrate':
      return `0x${secretHex}`;
    case 'solana':
      return base58.encode(keypair());
    case 'near':
      return `ed25519:${base58.encode(keypair())}`;
    case 'algorand':
      return base64.encode(keypair());
    case 'bitcoin':
    case 'btcfork':
      return wif(chain, secret());
    case 'stellar':
      return strkeySeed(secret());
    case 'sui':
      return bech32.encode('suiprivkey', bech32.toWords(new Uint8Array([0, ...secret()])));
    case 'aptos':
      return `ed25519-priv-0x${secretHex}`;
    case 'tezos':
      return b58check.encode(new Uint8Array([13, 15, 58, 7, ...secret()]));
    case 'stacks':
      return `${secretHex}01`;
    case 'xrpl':
      return `00${secretHex.toUpperCase()}`;
    case 'aeternity':
      return `sk_${b58check.encode(secret())}`;
    case 'waves':
      return base58.encode(secret());
    default:
      return secretHex;
  }
}

/** One line telling the user what the exported string is and where it imports. */
export function privateKeyFormat(chain: ChainInfo): string {
  switch (chain.family) {
    case 'evm':
    case 'hyperliquid':
      return 'Hex private key (MetaMask, Rabby and any EVM wallet).';
    case 'vechain':
      return 'Hex private key (VeWorld, Sync2).';
    case 'fuel':
      return 'Hex private key (Fuel Wallet).';
    case 'chromia':
    case 'gala':
      return 'Hex secp256k1 private key.';
    case 'starknet':
      return 'Stark private key (Argent X, Braavos import).';
    case 'starcoin':
      return 'Hex private key (StarMask).';
    case 'substrate':
      return 'Raw seed (polkadot.js "Raw seed" import).';
    case 'solana':
      return 'Base58 keypair (Phantom, Solflare, solana-keygen).';
    case 'near':
      return 'ed25519 keypair (near-cli, MyNearWallet).';
    case 'algorand':
      return 'Base64 keypair (algosdk secret key; Pera imports its 25-word form).';
    case 'bitcoin':
      return 'Compressed WIF (Sparrow, Electrum).';
    case 'btcfork':
      return `Compressed WIF for ${chain.name}.`;
    case 'stellar':
      return 'Secret seed (S…; Freighter, Lobstr).';
    case 'sui':
      return 'Bech32 private key (suiprivkey…; Slush, Suiet).';
    case 'aptos':
      return 'AIP-80 private key (Petra).';
    case 'tezos':
      return 'edsk secret key (Temple, Kukai).';
    case 'stacks':
      return 'Hex private key with the 01 compression suffix (Leather, Xverse).';
    case 'xrpl':
      return 'Hex private key with the 00 prefix (xrpl.js Wallet); family seeds differ.';
    case 'aeternity':
      return 'sk_ secret key (aepp-sdk, Superhero).';
    case 'waves':
      return 'Base58 Curve25519 private key (Waves Keeper account import).';
    case 'cosmos':
      return 'Hex private key (Keplr, Leap).';
    case 'tron':
      return 'Hex private key (TronLink).';
    case 'cardano':
      return 'Hex CIP-1852 payment signing key; Cardano wallets import phrases, not keys.';
    case 'chia':
      return 'Hex BLS wallet key (EIP-2333); Chia wallets import phrases, not keys.';
    case 'mixin':
      return 'Hex 64-byte kernel seed (spend || view; Mixin SDKs).';
    case 'qubic':
      return 'Hex SchnorrQ subseed; the Qubic wallet imports 55-letter seeds, not subseeds.';
    case 'ton':
      return 'Hex ed25519 seed; Tonkeeper imports phrases, not keys.';
    case 'multiversx':
      return 'Hex ed25519 seed (xPortal takes it as a PEM body).';
    case 'everscale':
      return 'Hex ed25519 seed (nekoton key).';
    case 'radix':
      return 'Hex ed25519 seed; the Radix Wallet imports phrases, not keys.';
    case 'icp':
      return 'Hex secp256k1 private key (dfx identity import needs a PEM wrapper).';
    case 'icon':
      return 'Hex private key (ICONex, Hana).';
    default:
      return 'Hex private key.';
  }
}

/**
 * Compressed WIF. Forks name their secret-key prefix outright; the Bitcoin
 * family follows the P2PKH + 0x80 rule, which is 0xef on every testnet.
 */
function wif(chain: ChainInfo, secret: Uint8Array): string {
  const p2pkh = typeof chain.extra?.p2pkhVersion === 'number' ? chain.extra.p2pkhVersion : 0;
  const body = new Uint8Array(34);
  body[0] =
    typeof chain.extra?.wifVersion === 'number' ? chain.extra.wifVersion : (p2pkh + 0x80) & 0xff;
  body.set(secret, 1);
  body[33] = 0x01;
  return b58check.encode(body);
}

/** Stellar StrKey: version 0x90 (seed), payload, CRC16-XModem little-endian, base32. */
function strkeySeed(seed: Uint8Array): string {
  const payload = new Uint8Array(1 + seed.length);
  payload[0] = 0x90;
  payload.set(seed, 1);
  let crc = 0;
  for (const byte of payload) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  const out = new Uint8Array(payload.length + 2);
  out.set(payload, 0);
  out[payload.length] = crc & 0xff;
  out[payload.length + 1] = crc >> 8;
  return base32.encode(out).replace(/=+$/, '');
}
