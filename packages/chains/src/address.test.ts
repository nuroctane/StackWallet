import { describe, expect, it } from 'vitest';

import { formatAmount, parseAmount, shortAddress } from './address.js';
import { bytesToHex, hexToBytes, secp256k1Compressed, secp256k1Uncompressed } from './keys.js';

describe('shortAddress', () => {
  it('truncates long addresses and leaves short ones alone', () => {
    expect(shortAddress('0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf')).toBe('0x7E5F…5Bdf');
    expect(shortAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 8, 6)).toBe(
      'bc1qw508…v8f3t4',
    );
    expect(shortAddress('short')).toBe('short');
  });

  it('keeps network prefixes and account names recognisable', () => {
    expect(shortAddress('account_rdx128y6j78mt0aqv6372evz28hrxp8mn06ccddkr7xppc88hyvynvjdwr')).toBe(
      'account_rdx128y…jdwr',
    );
    expect(shortAddress('cosmos1p3ucd3ptpw902fluyjzhq3ffgq4ntddac9sa3s')).toBe('cosmos1p3u…sa3s');
    expect(
      shortAddress(
        'addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x',
      ),
    ).toBe('addr1qx2…5a3x');
    expect(shortAddress('tnam1q9gr66cvu4hrzm0sd5kmlnjje82gs3xlfg3v6nu7')).toBe('tnam1q9g…6nu7');
    expect(shortAddress('ak_2a1j2Mk9YSmC1gioUq4PWRm3bsv887MbuRVwyv4KaUGoR1eiKi')).toBe(
      'ak_2a1…eiKi',
    );
    expect(shortAddress('alice.near')).toBe('alice.near');
    expect(shortAddress('vitalik.eth')).toBe('vitalik.eth');
    expect(shortAddress('eosio.token')).toBe('eosio.token');
    expect(shortAddress('7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU')).toBe('7xKXtg…gAsU');
  });
});

describe('formatAmount', () => {
  it('formats base units without floating point', () => {
    expect(formatAmount('1000000000000000000', 18)).toBe('1');
    expect(formatAmount('1500000000000000000', 18)).toBe('1.5');
    expect(formatAmount('1', 18)).toBe('0.000000000000000001');
    expect(formatAmount('123456789', 8)).toBe('1.23456789');
    expect(formatAmount('0', 6)).toBe('0');
    expect(formatAmount('5', 0)).toBe('5');
    expect(formatAmount('123456789012345678901234567890', 18)).toBe(
      '123456789012.34567890123456789',
    );
  });

  it('truncates to maxFraction and handles signs', () => {
    expect(formatAmount('1234567', 6, { maxFraction: 2 })).toBe('1.23');
    expect(formatAmount('1000000', 6, { maxFraction: 2, keepTrailingZeros: true })).toBe('1.00');
    expect(formatAmount('-2500000', 6)).toBe('-2.5');
    expect(formatAmount('-1', 6, { maxFraction: 2 })).toBe('0');
    expect(() => formatAmount('1.5', 6)).toThrow(TypeError);
  });
});

describe('parseAmount', () => {
  it('parses human decimals to base units', () => {
    expect(parseAmount('1', 18)).toBe('1000000000000000000');
    expect(parseAmount('1.5', 18)).toBe('1500000000000000000');
    expect(parseAmount('.5', 6)).toBe('500000');
    expect(parseAmount('0.000001', 6)).toBe('1');
    expect(parseAmount(' 42 ', 0)).toBe('42');
    expect(parseAmount('0', 8)).toBe('0');
  });

  it('rejects ambiguous input', () => {
    expect(parseAmount('1.1234567', 6)).toBeNull();
    expect(parseAmount('1,000', 6)).toBeNull();
    expect(parseAmount('-1', 6)).toBeNull();
    expect(parseAmount('1e5', 6)).toBeNull();
    expect(parseAmount('', 6)).toBeNull();
    expect(parseAmount('.', 6)).toBeNull();
    expect(parseAmount('1.5', 0)).toBeNull();
  });
});

describe('secp256k1 key encoding', () => {
  const gx = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  const gy = '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

  it('decompresses the generator point', () => {
    const full = secp256k1Uncompressed(hexToBytes('02' + gx));
    expect(bytesToHex(full)).toBe('04' + gx + gy);
    expect(bytesToHex(secp256k1Compressed(full))).toBe('02' + gx);
    expect(bytesToHex(secp256k1Compressed(hexToBytes(gx + gy)))).toBe('02' + gx);
  });

  it('picks the odd root for an 03 prefix', () => {
    const full = secp256k1Uncompressed(hexToBytes('03' + gx));
    const y = BigInt('0x' + bytesToHex(full.subarray(33)));
    expect(y & 1n).toBe(1n);
    expect(bytesToHex(secp256k1Compressed(full))).toBe('03' + gx);
  });

  it('rejects points off the curve and bad lengths', () => {
    expect(() => secp256k1Uncompressed(hexToBytes('04' + gx + gy.replace(/8$/, '9')))).toThrow(
      /not on secp256k1/,
    );
    expect(() => secp256k1Uncompressed(hexToBytes('05' + gx))).toThrow(/02 or 03/);
    expect(() => secp256k1Uncompressed(hexToBytes('0102'))).toThrow(/33, 64 or 65/);
    expect(() => hexToBytes('abc')).toThrow(TypeError);
  });
});
