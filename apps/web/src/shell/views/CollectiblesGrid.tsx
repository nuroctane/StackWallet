import { useEffect, useRef, useState, type RefObject } from 'react';
import { UNSUPPORTED_REASON, type Collectible } from '@stackwallet/collectibles';
import type { Account } from '@stackwallet/core-client';
import { Button, LoadingWord } from '@stackwallet/ui';

import { findChain } from '../../lib/chains.js';
import {
  collectiblesStore,
  setMediaMode,
  useCollectiblesVersion,
  useMedia,
  useMediaMode,
  type MediaMode,
} from '../../store/collectibles.js';
import { useRegistry } from '../../store/RegistryContext.js';

/**
 * Collectibles across `accounts`, on every chain with a keyless source.
 * Spam-flagged items stay hidden until asked for; images load only when a
 * card scrolls into view, through the vetted media loader.
 */
export function CollectiblesGrid({
  accounts,
  dense = false,
}: {
  accounts: readonly Account[];
  dense?: boolean;
}) {
  useCollectiblesVersion();
  const registry = useRegistry();
  const [showSuspicious, setShowSuspicious] = useState(false);
  const mode = useMediaMode();
  const accountKey = accounts.map((a) => a.id).join('|');

  useEffect(() => {
    for (const a of accounts) void collectiblesStore.load(a);
    // accountKey stands in for the array identity, which changes on every directory write.
  }, [accountKey]);

  const entries = accounts.map((a) => ({ account: a, entry: collectiblesStore.get(a) }));
  const loading = entries.some((e) => e.entry.loading);
  const errors = entries.filter((e) => e.entry.error);
  const all = entries.flatMap((e) => e.entry.items.map((item) => ({ item, account: e.account })));
  const suspicious = all.filter((x) => x.item.suspicious).length;
  const visible = showSuspicious ? all : all.filter((x) => !x.item.suspicious);
  const more = entries.filter((e) => e.entry.cursor && !e.entry.loading);
  const unsupportedFamilies = [
    ...new Set(entries.filter((e) => !e.entry.supported).map((e) => e.account.family)),
  ];

  return (
    <div className="flex min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-2 px-3 py-2 text-[11px] text-faint">
        <span>
          {loading ? <LoadingWord label="loading" /> : `${visible.length} shown`}
          {suspicious > 0 && !showSuspicious && ` · ${suspicious} flagged as spam hidden`}
        </span>
        <span className="flex-1" />
        <label
          className="inline-flex items-center gap-1"
          title="Every remote image reveals this device's IP to its host"
        >
          media
          <select
            className="h-6 rounded-sw-sm border border-edge bg-paper px-1 text-[11px] text-ink"
            value={mode}
            onChange={(e) => setMediaMode(e.target.value as MediaMode)}
          >
            <option value="all">all</option>
            <option value="vetted">vetted only</option>
            <option value="off">off</option>
          </select>
        </label>
        {suspicious > 0 && (
          <Button size="sm" variant="ghost" onClick={() => setShowSuspicious((v) => !v)}>
            {showSuspicious ? 'hide spam' : 'show spam'}
          </Button>
        )}
        <Button
          size="sm"
          variant="ghost"
          disabled={loading || accounts.length === 0}
          onClick={() => {
            for (const a of accounts) void collectiblesStore.load(a, true);
          }}
        >
          refresh
        </Button>
      </div>
      {errors.length > 0 && (
        <p className="px-3 pb-2 text-[11px] text-faint">
          {errors.length} {errors.length === 1 ? 'chain' : 'chains'} could not be read:{' '}
          {errors
            .map((e) => findChain(registry, e.account.chainId)?.name ?? e.account.chainId)
            .join(', ')}
          {errors.some((e) => e.account.family === 'solana') &&
            '. Public Solana endpoints refuse token-account queries; add an RPC that allows getTokenAccountsByOwner in the network element.'}
        </p>
      )}
      {unsupportedFamilies.map((f) =>
        UNSUPPORTED_REASON[f] ? (
          <p key={f} className="px-3 pb-2 text-[11px] text-faint">
            {UNSUPPORTED_REASON[f]}
          </p>
        ) : null,
      )}
      {visible.length === 0 && !loading ? (
        <p className="px-3 pb-3 text-[12px] text-faint">
          {accounts.length === 0 ? 'No accounts.' : 'No collectibles found on these accounts.'}
        </p>
      ) : (
        <ul
          className={`grid gap-2 px-3 pb-3 ${dense ? 'grid-cols-[repeat(auto-fill,minmax(112px,1fr))]' : 'grid-cols-[repeat(auto-fill,minmax(148px,1fr))]'}`}
        >
          {visible.map(({ item }) => (
            <Card key={item.key} item={item} chain={findChain(registry, item.chainId)?.name} />
          ))}
        </ul>
      )}
      {more.length > 0 && (
        <div className="px-3 pb-3">
          <Button
            size="sm"
            onClick={() => {
              for (const e of more) void collectiblesStore.loadMore(e.account);
            }}
          >
            load more
          </Button>
        </div>
      )}
    </div>
  );
}

function useInView<T extends Element>(): [RefObject<T | null>, boolean] {
  const ref = useRef<T | null>(null);
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el || seen) return;
    if (typeof IntersectionObserver === 'undefined') {
      setSeen(true);
      return;
    }
    const io = new IntersectionObserver(
      (es) => {
        if (es.some((e) => e.isIntersecting)) setSeen(true);
      },
      { rootMargin: '200px' },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [seen]);
  return [ref, seen];
}

function Card({ item, chain }: { item: Collectible; chain: string | undefined }) {
  const [ref, inView] = useInView<HTMLLIElement>();
  // Spam-flagged items never touch the network for media: their images are tracking beacons.
  const media = useMedia(inView && !item.suspicious ? item.image : null);
  return (
    <li
      ref={ref}
      className="flex min-w-0 flex-col overflow-hidden rounded-sw-sm border border-edge bg-surface"
      title={`${item.name} · ${item.collection} · ${chain ?? item.chainId}${item.suspicious ? ' · flagged as spam by the indexer' : ''}`}
    >
      <div className="relative aspect-square w-full bg-elevated">
        {media ? (
          <img
            src={media}
            alt=""
            draggable={false}
            className="h-full w-full object-cover"
            referrerPolicy="no-referrer"
          />
        ) : (
          <span className="absolute inset-0 flex items-center justify-center text-[10px] text-faint">
            {item.suspicious
              ? 'media blocked'
              : media === undefined && item.image && inView
                ? 'loading'
                : 'no image'}
          </span>
        )}
        {item.amount !== '1' && (
          <span className="absolute top-1 right-1 rounded-sw-sm bg-paper/80 px-1 text-[10px] text-ink">
            ×{item.amount}
          </span>
        )}
        {item.suspicious && (
          <span className="absolute top-1 left-1 rounded-sw-sm bg-danger-soft px-1 text-[10px] text-ink">
            spam?
          </span>
        )}
      </div>
      <div className="flex flex-col px-2 py-1.5 text-[11px]">
        <span className="truncate text-ink">{item.name}</span>
        <span className="truncate text-faint">
          {item.collection}
          {chain ? ` · ${chain}` : ''}
        </span>
      </div>
    </li>
  );
}
