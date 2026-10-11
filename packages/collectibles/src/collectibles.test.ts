import { describe, expect, it } from 'vitest';

import {
  cleanText,
  decodeDataUrl,
  directMediaUrl,
  gatewayCandidates,
  gatewayUrl,
  loadMedia,
  mediaUrl,
  metadataKey,
  parseBlockscoutPage,
  parseMetaplex,
} from './index.js';

const ch = (code: number) => String.fromCharCode(code);

describe('blockscout', () => {
  const raw = {
    items: [
      {
        id: '42',
        image_url: 'https://md.example/42.svg',
        metadata: { name: `Good ${ch(0x202e)}one` },
        token: {
          address_hash: '0x0000000000cf80E7Cf8Fa4480907f692177f8e06',
          name: 'Namefi',
          type: 'ERC-721',
          reputation: 'ok',
        },
        token_type: 'ERC-721',
        value: '1',
      },
      {
        id: '7',
        image_url: null,
        metadata: null,
        token: {
          address_hash: '0x1111111111111111111111111111111111111111',
          name: 'Claim $$$',
          reputation: 'scam',
        },
        token_type: 'ERC-1155',
        value: '3',
      },
      { id: 'x', token: { address_hash: 'nope' } },
    ],
    next_page_params: { token_id: '7', items_count: 50 },
  };

  it('maps items, strips hostile text and flags spam', () => {
    const page = parseBlockscoutPage('eip155:1', raw);
    expect(page.items).toHaveLength(2);
    expect(page.items[0]).toMatchObject({
      key: 'eip155:1:0x0000000000cf80e7cf8fa4480907f692177f8e06:42',
      standard: 'erc721',
      name: 'Good one',
      image: 'https://md.example/42.svg',
      suspicious: false,
    });
    expect(page.items[1]).toMatchObject({
      standard: 'erc1155',
      amount: '3',
      name: '#7',
      suspicious: true,
    });
    expect(page.cursor).toBe('token_id=7&items_count=50');
  });

  it('ends pagination when there are no next params', () => {
    expect(
      parseBlockscoutPage('eip155:1', { items: [], next_page_params: null }).cursor,
    ).toBeNull();
  });
});

describe('metaplex', () => {
  function encode(name: string, symbol: string, uri: string, pad = 0): Uint8Array {
    const enc = (s: string, width: number) => {
      const b = new TextEncoder().encode(s);
      const out = new Uint8Array(4 + b.length + width);
      new DataView(out.buffer).setUint32(0, b.length + width, true);
      out.set(b, 4);
      return out;
    };
    const parts = [new Uint8Array(65), enc(name, pad), enc(symbol, pad), enc(uri, pad)];
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }

  it('parses NUL-padded strings', () => {
    expect(parseMetaplex(encode('Mad Lad #1', 'MAD', 'https://x/1.json', 8))).toEqual({
      name: 'Mad Lad #1',
      symbol: 'MAD',
      uri: 'https://x/1.json',
    });
  });

  it('refuses truncated accounts', () => {
    expect(parseMetaplex(new Uint8Array(70))).toBeNull();
  });

  it('derives the metadata PDA for a mint', () => {
    // USDC's metadata account, as recorded on chain.
    expect(metadataKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v')).toBe(
      '5x38Kp4hvdomTCnCrAny4UtMUt5rQBdB6px2K1Ui45Wq',
    );
  });
});

describe('media', () => {
  it('only accepts https and content-addressed urls', () => {
    expect(mediaUrl('http://x/a.png')).toBeNull();
    expect(mediaUrl('javascript:alert(1)')).toBeNull();
    expect(mediaUrl('https://user:pw@x/a.png')).toBeNull();
    expect(mediaUrl('ipfs://bafy/1.png')).toBe('https://ipfs.filebase.io/ipfs/bafy/1.png');
    expect(gatewayUrl('ipfs://ipfs/bafy')).toBe('https://ipfs.filebase.io/ipfs/bafy');
    // Gateway URLs found in metadata are retried on the other gateways too.
    expect(gatewayCandidates('https://ipfs.io/ipfs/bafy/2.png')).toEqual([
      'https://ipfs.filebase.io/ipfs/bafy/2.png',
      'https://gateway.pinata.cloud/ipfs/bafy/2.png',
      'https://ipfs.io/ipfs/bafy/2.png',
    ]);
    expect(directMediaUrl('javascript:alert(1)')).toBeNull();
    expect(directMediaUrl('https://x/a.png')).toBe('https://x/a.png');
    expect(gatewayUrl('ar://abc')).toBe('https://arweave.net/abc');
  });

  it('decodes image data urls and refuses everything else', () => {
    const svg = decodeDataUrl(`data:image/svg+xml;base64,${btoa('<svg/>')}`);
    expect(svg.ok && svg.blob.type).toBe('image/svg+xml');
    expect(decodeDataUrl('data:text/html,<script>').ok).toBe(false);
    expect(decodeDataUrl('data:image/png;base64,AAAA', 2).ok).toBe(false);
  });

  it('refuses non-image responses and oversize bodies', async () => {
    const respond = (type: string, size: number): typeof fetch =>
      (async () =>
        new Response(new Uint8Array(size), { headers: { 'content-type': type } })) as typeof fetch;
    expect(await loadMedia('https://x/a', { fetch: respond('text/html', 10) })).toMatchObject({
      ok: false,
    });
    expect(
      await loadMedia('https://x/a', { fetch: respond('image/png', 64), maxBytes: 32 }),
    ).toEqual({
      ok: false,
      reason: 'too large',
    });
    const ok = await loadMedia('https://x/a', { fetch: respond('image/png; q=1', 16) });
    // A dead gateway falls through to the next one.
    let n = 0;
    const flaky = (async () => {
      n += 1;
      if (n === 1) throw new TypeError('Failed to fetch');
      return new Response(new Uint8Array(4), { headers: { 'content-type': 'image/gif' } });
    }) as typeof fetch;
    const viaSecond = await loadMedia('ipfs://bafy/x.gif', { fetch: flaky });
    expect(viaSecond.ok).toBe(true);
    expect(n).toBe(2);
    expect(ok.ok && ok.blob.size).toBe(16);
  });
});

describe('text', () => {
  it('strips control and bidi characters and caps length', () => {
    expect(cleanText(`a${ch(0x200b)}b${ch(0x07)}c`)).toBe('abc');
    expect(cleanText('x'.repeat(200), 10)).toHaveLength(10);
    expect(cleanText({})).toBe('');
  });
});
