import { MockLanguageModelV4 } from 'ai/test';
import { describe, expect, it } from 'vitest';

import { runAgentTurn, type AgentHost } from './run.js';
import { sanitizeUntrusted } from './sanitize.js';

const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: 0 },
};

function scripted(...steps: Array<{ tool?: [string, unknown]; text?: string }>) {
  let i = 0;
  return new MockLanguageModelV4({
    doGenerate: async () => {
      const s = steps[Math.min(i++, steps.length - 1)]!;
      return {
        content: s.tool
          ? [
              {
                type: 'tool-call',
                toolCallId: `c${i}`,
                toolName: s.tool[0],
                input: JSON.stringify(s.tool[1]),
              },
            ]
          : [{ type: 'text', text: s.text ?? '' }],
        finishReason: { unified: s.tool ? 'tool-calls' : 'stop', raw: undefined },
        usage,
        warnings: [],
      };
    },
  });
}

function host(proposed: unknown[]): AgentHost {
  return {
    wallets: () => [
      {
        id: 'w1',
        name: 'Hot\u202e',
        kind: 'single',
        accounts: [{ chainId: 'eip155:11155111', address: '0xabc', chain: 'Sepolia' }],
      },
      { id: 'w2', name: 'Cold', kind: 'single', accounts: [] },
    ],
    balances: async () => [
      { chainId: 'eip155:11155111', chain: 'Sepolia', asset: 'native', symbol: 'ETH', amount: '1' },
    ],
    label: (address) =>
      address === '0xfriend'
        ? { label: 'Friend', source: 'contact' }
        : { label: null, source: 'none' },
    proposeTransfer: async (input) => {
      proposed.push(input);
      return { ok: true, state: 'awaiting', txId: 't' };
    },
  };
}

const grant = { walletIds: ['w1'], allowPropose: true, maxSteps: 5, maxProposals: 1 };

describe('agent turn', () => {
  it('reads only granted wallets, sanitised', async () => {
    const r = await runAgentTurn({
      model: scripted({ tool: ['list_wallets', {}] }, { text: 'You have one wallet.' }),
      host: host([]),
      grant,
      history: [],
      message: 'what do I have?',
      counter: { proposals: 0 },
    });
    expect(r.text).toBe('You have one wallet.');
    const out = r.trace[0]!.output as { id: string; name: string }[];
    expect(out.map((w) => w.id)).toEqual(['w1']);
    expect(out[0]!.name).toBe('Hot');
  });

  it('proposes, flags unknown destinations and stops at the cap', async () => {
    const proposed: { untrustedDestination: boolean }[] = [];
    const input = {
      walletId: 'w1',
      chainId: 'eip155:11155111',
      to: '0xstranger',
      asset: 'native',
      amount: '0.1',
      rationale: 'asked',
    };
    const r = await runAgentTurn({
      model: scripted(
        { tool: ['propose_transfer', input] },
        { tool: ['propose_transfer', { ...input, to: '0xfriend' }] },
        { text: 'Proposed; approve it in the queue.' },
      ),
      host: host(proposed),
      grant,
      history: [],
      message: 'send 0.1',
      counter: { proposals: 0 },
    });
    expect(proposed).toHaveLength(1);
    expect(proposed[0]!.untrustedDestination).toBe(true);
    expect(r.trace[1]!.output).toMatchObject({ error: expect.stringMatching(/cap/) });
    expect(r.proposals).toBe(1);
  });

  it('cannot touch wallets outside the grant or propose without permission', async () => {
    const proposed: unknown[] = [];
    const r = await runAgentTurn({
      model: scripted({ tool: ['get_balances', { walletId: 'w2' }] }, { text: 'done' }),
      host: host(proposed),
      grant: { ...grant, allowPropose: false },
      history: [],
      message: 'x',
      counter: { proposals: 0 },
    });
    expect(r.trace[0]!.output).toEqual({ error: 'wallet not granted' });
  });

  it('strips hidden characters', () => {
    expect(sanitizeUntrusted('a\u200bb\u202ec\u0007', 10)).toBe('abc');
    expect(sanitizeUntrusted('x'.repeat(5), 3)).toBe('xxx…');
  });
});
