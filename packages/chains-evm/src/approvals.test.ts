import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import {
  APPROVAL_FOR_ALL_TOPIC,
  APPROVAL_TOPIC,
  approvalLogsUrl,
  candidatesFromLogs,
  parseLogsResponse,
  revokeCalldata,
  scanApprovals,
  verifyCandidates,
  type ApprovalLog,
  type ContractRead,
} from './approvals.js';

const OWNER = '0x1111111111111111111111111111111111111111';
const SPENDER = '0x2222222222222222222222222222222222222222';
const OTHER = '0x3333333333333333333333333333333333333333';
const TOKEN = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const NFT = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

const t = (addr: string) => `0x${addr.slice(2).padStart(64, '0')}`;
const w = (n: bigint) => `0x${n.toString(16).padStart(64, '0')}`;
const MAX = (1n << 256n) - 1n;

let idx = 0;
function log(partial: Partial<ApprovalLog> & Pick<ApprovalLog, 'topics'>): ApprovalLog {
  idx += 1;
  return {
    address: TOKEN,
    data: '0x',
    blockNumber: idx,
    logIndex: 0,
    transactionHash: `0x${idx.toString(16).padStart(64, '0')}`,
    ...partial,
  };
}

describe('approval discovery', () => {
  it('uses the canonical event topics', () => {
    const topic = (sig: string) => `0x${bytesToHex(keccak_256(new TextEncoder().encode(sig)))}`;
    expect(APPROVAL_TOPIC).toBe(topic('Approval(address,address,uint256)'));
    expect(APPROVAL_FOR_ALL_TOPIC).toBe(topic('ApprovalForAll(address,address,bool)'));
  });

  it('keeps the latest event per allowance, token id and operator', () => {
    const logs = [
      log({ topics: [APPROVAL_TOPIC, t(OWNER), t(SPENDER)], data: w(MAX) }),
      log({ topics: [APPROVAL_TOPIC, t(OWNER), t(OTHER)], data: w(5n) }),
      // A later zero approval closes the first allowance.
      log({ topics: [APPROVAL_TOPIC, t(OWNER), t(OTHER)], data: w(0n) }),
      log({ address: NFT, topics: [APPROVAL_TOPIC, t(OWNER), t(SPENDER), w(7n)] }),
      log({ address: NFT, topics: [APPROVAL_FOR_ALL_TOPIC, t(OWNER), t(OTHER)], data: w(1n) }),
      // Someone else's approval on the same contract is not ours.
      log({ topics: [APPROVAL_TOPIC, t(OTHER), t(SPENDER)], data: w(9n) }),
    ];
    const c = candidatesFromLogs(OWNER, logs);
    expect(c.map((x) => [x.kind, x.token, x.spender, x.tokenId ?? null])).toEqual([
      ['erc20', TOKEN, SPENDER, null],
      ['nft', NFT, SPENDER, '7'],
      ['operator', NFT, OTHER, null],
    ]);
  });

  it('parses indexer answers including the empty one', () => {
    expect(parseLogsResponse({ status: '0', message: 'No logs found', result: [] })).toEqual([]);
    const parsed = parseLogsResponse({
      status: '1',
      message: 'OK',
      result: [
        {
          address: TOKEN.toUpperCase().replace('0X', '0x'),
          topics: [APPROVAL_TOPIC, t(OWNER), t(SPENDER), null],
          data: w(1n),
          blockNumber: '0x10',
          logIndex: '0x2',
          transactionHash: `0x${'ab'.repeat(32)}`,
        },
      ],
    });
    expect(parsed[0]).toMatchObject({ address: TOKEN, blockNumber: 16, logIndex: 2 });
    expect(parsed[0]!.topics).toHaveLength(3);
    expect(() =>
      parseLogsResponse({ status: '0', message: 'NOTOK', result: 'rate limited' }),
    ).toThrow();
  });

  it('builds the owner-filtered log query', () => {
    const url = new URL(approvalLogsUrl('https://eth.blockscout.com/', OWNER, APPROVAL_TOPIC));
    expect(url.pathname).toBe('/api');
    expect(url.searchParams.get('topic1')).toBe(t(OWNER));
    expect(url.searchParams.get('topic0_1_opr')).toBe('and');
  });
});

describe('approval verification', () => {
  const candidates = candidatesFromLogs(OWNER, [
    log({ topics: [APPROVAL_TOPIC, t(OWNER), t(SPENDER)], data: w(MAX) }),
    log({ topics: [APPROVAL_TOPIC, t(OWNER), t(OTHER)], data: w(10n) }),
    log({ address: NFT, topics: [APPROVAL_TOPIC, t(OWNER), t(SPENDER), w(7n)] }),
    log({ address: NFT, topics: [APPROVAL_FOR_ALL_TOPIC, t(OWNER), t(OTHER)], data: w(1n) }),
  ]);

  it('drops what the contract says is closed and keeps what it says is open', async () => {
    const read: ContractRead = async (to, data) => {
      if (data.startsWith('0xdd62ed3e')) return data.endsWith(OTHER.slice(2)) ? w(0n) : w(MAX);
      if (data.startsWith('0x081812fc')) return t(SPENDER);
      if (data.startsWith('0x6352211e')) return t(OTHER); // the NFT was transferred away
      if (data.startsWith('0xe985e9c5')) return w(1n);
      throw new Error(`unexpected ${to}`);
    };
    const open = await verifyCandidates('eip155:1', OWNER, candidates, read);
    expect(open.map((o) => [o.kind, o.spender, o.unlimited, o.verified])).toEqual([
      ['erc20', SPENDER, true, true],
      ['operator', OTHER, true, true],
    ]);
  });

  it('keeps candidates open when the contract cannot be read', async () => {
    const open = await verifyCandidates('eip155:1', OWNER, candidates, async () => {
      throw new Error('timeout');
    });
    expect(open).toHaveLength(4);
    expect(open.every((o) => !o.verified)).toBe(true);
  });

  it('treats a reverted NFT read as a burned token', async () => {
    const open = await verifyCandidates('eip155:1', OWNER, [candidates[2]!], async () => {
      throw new Error('execution reverted');
    });
    expect(open).toEqual([]);
  });

  it('scans end to end through the indexer and the contract', async () => {
    const fetch = (async (input: RequestInfo | URL) => {
      const topic0 = new URL(String(input)).searchParams.get('topic0');
      const result =
        topic0 === APPROVAL_TOPIC
          ? [
              {
                address: TOKEN,
                topics: [APPROVAL_TOPIC, t(OWNER), t(SPENDER)],
                data: w(3n),
                blockNumber: '1',
                transactionHash: `0x${'cd'.repeat(32)}`,
              },
            ]
          : [];
      return new Response(JSON.stringify({ status: '1', message: 'OK', result }));
    }) as typeof globalThis.fetch;
    const scan = await scanApprovals({
      chainId: 'eip155:1',
      owner: OWNER,
      indexer: 'https://eth.blockscout.com',
      read: async () => w(3n),
      now: () => 42,
      fetchOptions: { fetch },
    });
    expect(scan).toMatchObject({ chainId: 'eip155:1', truncated: false, checkedAtMs: 42 });
    expect(scan.open).toHaveLength(1);
    expect(scan.open[0]).toMatchObject({ amount: '3', unlimited: false, verified: true });
  });

  it('builds revoke calldata for each kind', () => {
    expect(revokeCalldata({ kind: 'erc20', spender: SPENDER })).toBe(
      `0x095ea7b3${t(SPENDER).slice(2)}${'0'.repeat(64)}`,
    );
    expect(revokeCalldata({ kind: 'operator', spender: OTHER })).toBe(
      `0xa22cb465${t(OTHER).slice(2)}${'0'.repeat(64)}`,
    );
    expect(revokeCalldata({ kind: 'nft', spender: SPENDER, tokenId: '7' })).toBe(
      `0x095ea7b3${'0'.repeat(64)}${w(7n).slice(2)}`,
    );
  });
});
