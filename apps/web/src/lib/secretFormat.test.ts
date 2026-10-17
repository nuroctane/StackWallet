import { base32 } from '@scure/base';
import { catalogChain, CHAIN_CATALOG } from '@stackwallet/chains';
import { describe, expect, it } from 'vitest';

import { formatPrivateKey, privateKeyFormat } from './secretFormat.js';

const one = '0000000000000000000000000000000000000000000000000000000000000001';
const seed = '11'.repeat(32);
const pub = '22'.repeat(32);
const chain = (id: string) => catalogChain(id)!;

describe('private key formats', () => {
  it('encodes the BIP32 test key as compressed WIF', () => {
    // Private key 1 (the generator point) has well-known encodings.
    const btc = chain('bip122:000000000019d6689c085ae165831e93');
    expect(formatPrivateKey(btc, one, '')).toBe(
      'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
    );
    expect(formatPrivateKey(chain('eip155:1'), one, '')).toBe(`0x${one}`);
  });

  it('uses the fork version byte on mainnets and 0xef on every fork testnet', () => {
    // Dash compressed WIF starts with X (0xcc); every testnet WIF starts with c (0xef).
    expect(formatPrivateKey(chain('btcfork:dash-mainnet'), one, '')).toMatch(/^X/);
    expect(formatPrivateKey(chain('btcfork:dash-testnet'), one, '')).toMatch(/^c/);
    expect(formatPrivateKey(chain('btcfork:zcash-testnet'), one, '')).toMatch(/^c/);
    expect(formatPrivateKey(chain('bip122:00000008819873e925422c1ff0f99f7c'), one, '')).toMatch(
      /^c/,
    );
  });

  it('packs a Solana keypair as 64 bytes of base58', () => {
    const sol = chain('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp');
    const out = formatPrivateKey(sol, seed, pub);
    expect(out.length).toBeGreaterThan(80);
    expect(formatPrivateKey(chain('near:mainnet'), seed, pub)).toBe(`ed25519:${out}`);
  });

  it('wraps ed25519 seeds the way each family imports them', () => {
    expect(formatPrivateKey(chain('sui:mainnet'), seed, pub)).toMatch(/^suiprivkey1[a-z0-9]{59}$/);
    expect(formatPrivateKey(chain('aptos:1'), seed, pub)).toBe(`ed25519-priv-0x${seed}`);
    expect(formatPrivateKey(chain('tezos:NetXdQprcVkpaWU'), seed, pub)).toMatch(
      /^edsk[1-9A-HJ-NP-Za-km-z]{50}$/,
    );
    expect(formatPrivateKey(chain('polkadot:91b171bb158e2d3848fa23a9f1c25182'), seed, pub)).toBe(
      `0x${seed}`,
    );
    expect(formatPrivateKey(chain('aet:ae_mainnet'), seed, pub)).toMatch(/^sk_/);
    const algo = formatPrivateKey(chain('algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k'), seed, pub);
    expect(algo).toHaveLength(88);
  });

  it('wraps secp256k1 keys the way each family imports them', () => {
    expect(formatPrivateKey(chain('stacks:1'), one, '')).toBe(`${one}01`);
    expect(formatPrivateKey(chain('xrpl:0'), one, '')).toBe(`00${one.toUpperCase()}`);
    expect(formatPrivateKey(chain('starknet:SN_MAIN'), one, '')).toBe(`0x${one}`);
    expect(formatPrivateKey(chain('cosmos:cosmoshub-4'), one, '')).toBe(one);
  });

  it('emits a Stellar secret seed that decodes back to the seed with a valid checksum', () => {
    const out = formatPrivateKey(chain('stellar:pubnet'), seed, pub);
    expect(out).toMatch(/^S[A-Z2-7]{55}$/);
    const bytes = base32.decode(out);
    expect(bytes[0]).toBe(0x90);
    expect(Buffer.from(bytes.slice(1, 33)).toString('hex')).toBe(seed);
    // CRC16-XModem over version || seed, little-endian.
    let crc = 0;
    for (const b of bytes.slice(0, 33)) {
      crc ^= b << 8;
      for (let i = 0; i < 8; i++)
        crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
    expect([bytes[33], bytes[34]]).toEqual([crc & 0xff, crc >> 8]);
  });

  it('describes the export for every catalogued family', () => {
    const families = new Set(CHAIN_CATALOG.map((c) => c.family));
    for (const family of families) {
      const c = CHAIN_CATALOG.find((x) => x.family === family)!;
      expect(privateKeyFormat(c).length, family).toBeGreaterThan(8);
    }
  });
});
