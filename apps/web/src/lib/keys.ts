import type { ChainInfo } from '@stackwallet/chains';
import type { ChainFamily, Curve } from '@stackwallet/core-client';

export interface StandardPath {
  curve: Extract<Curve, 'secp256k1' | 'ed25519'>;
  path: string;
}

/**
 * The derivation path other wallets use for the first account on `chain`, so
 * an exported phrase restores the same addresses in MetaMask, Phantom, Keplr
 * or any BIP84 Bitcoin wallet.
 */
export function standardPath(chain: ChainInfo): StandardPath | null {
  const coin = typeof chain.extra?.coinType === 'number' ? chain.extra.coinType : null;
  switch (chain.family) {
    case 'evm':
      return { curve: 'secp256k1', path: "m/44'/60'/0'/0/0" };
    case 'solana':
      return { curve: 'ed25519', path: "m/44'/501'/0'/0'" };
    case 'bitcoin':
      if (coin === null) return null;
      // Native SegWit (BIP84) where the chain has it, legacy BIP44 otherwise.
      return {
        curve: 'secp256k1',
        path: chain.extra?.segwit ? `m/84'/${coin}'/0'/0/0` : `m/44'/${coin}'/0'/0/0`,
      };
    case 'cosmos':
      return coin === null ? null : { curve: 'secp256k1', path: `m/44'/${coin}'/0'/0/0` };
    case 'tron':
      return { curve: 'secp256k1', path: "m/44'/195'/0'/0/0" };
    default:
      return familyPath(chain, 0);
  }
}

/**
 * Path of account `index` on `chain`, following each family's common wallet
 * convention so the same phrase shows the same accounts elsewhere: MetaMask
 * and Keplr step the address index, Phantom the account, BIP84 the account.
 * Index 0 is always `standardPath`.
 */
export function accountPath(chain: ChainInfo, index: number): StandardPath | null {
  const base = standardPath(chain);
  if (!base || !Number.isInteger(index) || index < 0 || index >= 2 ** 31) return null;
  if (index === 0) return base;
  const coin = typeof chain.extra?.coinType === 'number' ? chain.extra.coinType : null;
  switch (chain.family) {
    case 'evm':
      return { curve: 'secp256k1', path: `m/44'/60'/0'/0/${index}` };
    case 'solana':
      return { curve: 'ed25519', path: `m/44'/501'/${index}'/0'` };
    case 'bitcoin':
      return chain.extra?.segwit
        ? { curve: 'secp256k1', path: `m/84'/${coin}'/${index}'/0/0` }
        : { curve: 'secp256k1', path: `m/44'/${coin}'/${index}'/0/0` };
    case 'cosmos':
      return { curve: 'secp256k1', path: `m/44'/${coin}'/0'/0/${index}` };
    case 'tron':
      return { curve: 'secp256k1', path: `m/44'/195'/0'/0/${index}` };
    default:
      return familyPath(chain, index);
  }
}

/**
 * Newer families: one path template each, index stepped where that family's main wallets step it.
 * Ed25519 paths are hardened at every level (SLIP-10).
 */
const FAMILY_PATHS: Partial<
  Record<ChainFamily, { curve: StandardPath['curve']; at(i: number, coin: number | null): string }>
> = {
  // BIP44 multi-chain wallets (Ledger, Trust) for Polkadot; sr25519 wallets derive differently.
  substrate: { curve: 'ed25519', at: (i) => `m/44'/354'/0'/0'/${i}'` },
  // SEP-0005: Lobstr, Freighter, Solar, Ledger.
  stellar: { curve: 'ed25519', at: (i) => `m/44'/148'/${i}'` },
  // Petra, Pontem, Martian; Movement wallets reuse the Aptos path.
  aptos: { curve: 'ed25519', at: (i) => `m/44'/637'/${i}'/0'/0'` },
  // Slush (Sui Wallet), Suiet, Phantom and the Mysten SDK step the last level; IOTA Rebased
  // wallets use the same shape under coin type 4218.
  sui: { curve: 'ed25519', at: (i, coin) => `m/44'/${coin ?? 784}'/0'/0'/${i}'` },
  // MyNearWallet, Meteor and near-seed-phrase; the Ledger NEAR app nests two more levels.
  near: { curve: 'ed25519', at: (i) => `m/44'/397'/${i}'` },
  // SLIP-10 under coin 283. Pera/Defly 25-word phrases and Ledger's BIP32-Ed25519 do not match.
  algorand: { curve: 'ed25519', at: (i) => `m/44'/283'/${i}'/0'/0'` },
  // Trust Wallet and Ledger; Tonkeeper-style TON mnemonics derive differently.
  ton: { curve: 'ed25519', at: (i) => `m/44'/607'/${i}'` },
  // CIP-1852 payment key (Yoroi, Eternl, Lace). The core derives it with Icarus BIP32-Ed25519, not
  // SLIP-10, and returns payment || stake public keys so the account gets its base address.
  cardano: { curve: 'ed25519', at: (i) => `m/1852'/1815'/${i}'/0/0` },
  // BIP44 under SLIP-44 194 for mnemonic EOS-lineage wallets; the account is an on-chain name the key controls.
  antelope: { curve: 'secp256k1', at: (i) => `m/44'/194'/0'/0/${i}` },
  // xPortal, the MultiversX web wallet and sdk-core.
  multiversx: { curve: 'ed25519', at: (i) => `m/44'/508'/0'/0'/${i}'` },
  // Temple, Kukai and Umami (Ed25519 tz1).
  tezos: { curve: 'ed25519', at: (i) => `m/44'/1729'/${i}'/0'` },
  // Leather and Xverse.
  stacks: { curve: 'secp256k1', at: (i) => `m/44'/5757'/0'/0/${i}` },
  // VeWorld, Sync2 and the VeChain SDK HDKey default.
  vechain: { curve: 'secp256k1', at: (i) => `m/44'/818'/0'/0/${i}` },
  // Standard Ethereum accounts; MetaMask and Rabby use these to sign into Hyperliquid.
  hyperliquid: { curve: 'secp256k1', at: (i) => `m/44'/60'/0'/0/${i}` },
  // Braavos and Argent X prefix. The core grinds the secp256k1 secret into the Stark key
  // (EIP-2645); the account public key is the Stark key, not the SEC1 point.
  starknet: { curve: 'secp256k1', at: (i) => `m/44'/9004'/0'/0/${i}` },
  // IIP-48, used by ICONex, Hana, MyIconWallet and the Ledger ICX app (all hardened).
  icon: { curve: 'secp256k1', at: (i) => `m/44'/4801368'/0'/0'/${i}'` },
  // Everscale and Venom share SLIP-44 396 (nekoton wallets use it for both), all hardened.
  everscale: { curve: 'ed25519', at: (i) => `m/44'/396'/0'/0'/${i}'` },
  // SLIP-44 5741564, all hardened; the Waves key is derived from the seed, not the point.
  waves: { curve: 'ed25519', at: (i) => `m/44'/5741564'/0'/0'/${i}'` },
  // CAP-26, the official Radix Wallet path; network 2 is Stokenet (1 is mainnet).
  radix: { curve: 'ed25519', at: (i) => `m/44'/1022'/2'/525'/1460'/${i}'` },
  // SLIP-44 223 (Plug and most ICP wallets); the account id comes from the SEC1 key.
  icp: { curve: 'secp256k1', at: (i) => `m/44'/223'/0'/0/${i}` },
  // SLIP-44 877, all-hardened, matching the official wallet's transparent accounts.
  namada: { curve: 'ed25519', at: (i) => `m/44'/877'/0'/0'/${i}'` },
  // No SLIP-44 coin type exists for Keeta (its own scheme is HKDF-SHA3, not
  // BIP-32); 9797 is an unregistered choice, documented as ours.
  keeta: { curve: 'secp256k1', at: (i) => `m/44'/9797'/0'/0/${i}` },
  // Non-standard: Chromia has no SLIP-44 coin type and its official wallet is
  // EVM-key-centric, so CHR accounts reuse the EVM path deliberately.
  chromia: { curve: 'secp256k1', at: (i) => `m/44'/60'/0'/0/${i}` },
  // The official obyte-gui-wallet derives at Bitcoin's coin type; SLIP-44's
  // 592 is unused by any Obyte software.
  obyte: { curve: 'secp256k1', at: (i) => `m/44'/0'/0'/0/${i}` },
  // StarMask's path; all-hardened SLIP-10.
  starcoin: { curve: 'ed25519', at: (i) => `m/44'/101010'/0'/0'/${i}'` },
  // aelf-sdk default BIP44Path; used by NightELF and Portkey.
  aelf: { curve: 'secp256k1', at: (i) => `m/44'/1616'/0'/0/${i}` },
  // fuels HDWallet default; index hardened, non-hardened tail.
  fuel: { curve: 'secp256k1', at: (i) => `m/44'/1179993420'/${i}'/0/0` },
  // EIP-2334 Chia wallet keys (BLS12-381, all-hardened); the core derives
  // these by EIP-2333 through a provenance route, not SLIP-10.
  chia: { curve: 'ed25519', at: (i) => `m/12381'/8444'/2'/${i}'` },
  // aepp-sdk hd-wallet, AirGap and the Ledger app; all-hardened SLIP-10.
  aeternity: { curve: 'ed25519', at: (i) => `m/44'/457'/0'/0'/${i}'` },
  // @alephium/web3-wallet getHDWalletPath; third level is the key type (0 = ECDSA).
  alephium: { curve: 'secp256k1', at: (i) => `m/44'/1234'/0'/0/${i}` },
  // EIP-3, used by Nautilus and the reference wallet; non-hardened tail.
  ergo: { curve: 'secp256k1', at: (i) => `m/44'/429'/0'/0/${i}` },
  // GalaChain uses Ethereum keys verbatim (`eth|` refs), so the EVM path applies.
  gala: { curve: 'secp256k1', at: (i) => `m/44'/60'/0'/0/${i}` },
  // SLIP-44 2365, all-hardened SLIP-10; the kernel derives spend/view from sha512(secret).
  mixin: { curve: 'ed25519', at: (i) => `m/44'/2365'/0'/0'/${i}'` },
  // SLIP-44 83293, all-hardened SLIP-10; the derived seed is the SchnorrQ
  // subseed directly (Qubic's FourQ is not an HD curve).
  qubic: { curve: 'ed25519', at: (i) => `m/44'/83293'/0'/0'/${i}'` },
  // SLIP-44 per fork (BCH 145, Dash 5, Zcash 133, DefiChain 1129, Verus 141);
  // no fork has segwit, so the plain BIP44 template fits all of them.
  btcfork: { curve: 'secp256k1', at: (i, coin) => `m/44'/${coin}'/0'/0/${i}` },
  // Xaman, Trust Wallet and Ledger (BIP44); XRPL family seeds derive differently.
  xrpl: { curve: 'secp256k1', at: (i) => `m/44'/144'/0'/0/${i}` },
};

function familyPath(chain: ChainInfo, index: number): StandardPath | null {
  const p = FAMILY_PATHS[chain.family];
  const coin = typeof chain.extra?.coinType === 'number' ? chain.extra.coinType : null;
  return p ? { curve: p.curve, path: p.at(index, coin) } : null;
}

/** The lowest account index on `chainId` that the wallet does not use yet. */
export function nextAccountIndex(
  chain: ChainInfo,
  usedPaths: readonly (string | null | undefined)[],
): number {
  const used = new Set(usedPaths.filter(Boolean));
  for (let i = 0; i < 1000; i++) {
    const p = accountPath(chain, i);
    if (p && !used.has(p.path)) return i;
  }
  return 1000;
}
