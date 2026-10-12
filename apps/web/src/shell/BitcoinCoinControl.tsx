import { useEffect, useRef, useState } from 'react';
import {
  readBitcoinCoins,
  type BitcoinAdapter,
  type BitcoinCoin,
  type BitcoinPrepareOptions,
} from '@stackwallet/chains-bitcoin';
import { Button, Input } from '@stackwallet/ui';

export function BitcoinCoinControl({
  adapter,
  from,
  disabled,
  onChange,
}: {
  adapter: BitcoinAdapter;
  from: string;
  disabled: boolean;
  onChange: (options: BitcoinPrepareOptions, valid: boolean) => void;
}) {
  const [manual, setManual] = useState(false);
  const [coins, setCoins] = useState<BitcoinCoin[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [fee, setFee] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [shown, setShown] = useState(100);
  const generation = useRef(0);
  useEffect(
    () => () => {
      ++generation.current;
    },
    [],
  );

  const update = (nextManual: boolean, keys: string[], rate: string) => {
    const validFee =
      rate === '' || (/^[0-9]+$/.test(rate) && Number(rate) >= 1 && Number(rate) <= 100);
    const inputs = keys.map((key) => {
      const [txid, vout] = key.split(':');
      return { txid: txid!, vout: Number(vout) };
    });
    onChange(
      {
        ...(nextManual ? { inputs } : {}),
        ...(rate !== '' && validFee ? { feeRate: Number(rate) } : {}),
      },
      validFee && (!nextManual || (keys.length > 0 && keys.length <= 8)),
    );
  };
  const refresh = async () => {
    const current = ++generation.current;
    setLoading(true);
    setError(null);
    setSelected([]);
    setCoins([]);
    setLoaded(false);
    update(manual, [], fee);
    try {
      const result = await readBitcoinCoins(adapter, from);
      if (current !== generation.current) return;
      setCoins(result);
      setLoaded(true);
      setShown(100);
    } catch (err) {
      if (current === generation.current)
        setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (current === generation.current) setLoading(false);
    }
  };
  const total = coins
    .filter((c) => selected.includes(`${c.txid}:${c.vout}`))
    .reduce((n, c) => n + BigInt(c.value), 0n);
  return (
    <details className="min-w-0 rounded-sw-sm border border-edge p-3 text-[12px]">
      <summary className="min-h-11 cursor-pointer py-3 text-muted">
        Coin control and fee rate · Signet
      </summary>
      <div className="space-y-3">
        <p className="break-words text-faint">
          Loading coins sends this address to the configured Signet endpoint. These are endpoint
          observations; preparation rechecks funding bytes and spend status. Rust validates and
          reserves the actual inputs.
        </p>
        <label className="flex min-h-11 items-center gap-2 text-muted">
          <input
            type="checkbox"
            checked={manual}
            disabled={disabled}
            onChange={(e) => {
              setManual(e.target.checked);
              setSelected([]);
              update(e.target.checked, [], fee);
            }}
          />
          Choose confirmed inputs manually (1–8)
        </label>
        <label className="flex flex-col gap-1 text-muted">
          Fee rate in sats/vB · blank uses endpoint recommendation
          <Input
            value={fee}
            disabled={disabled}
            inputMode="numeric"
            placeholder="recommended"
            onChange={(e) => {
              setFee(e.target.value);
              update(manual, selected, e.target.value);
            }}
          />
        </label>
        {fee !== '' && (!/^[0-9]+$/.test(fee) || Number(fee) < 1 || Number(fee) > 100) && (
          <p role="alert" className="text-danger">
            Use an integer from 1 to 100 sats/vB.
          </p>
        )}
        {manual && (
          <>
            <Button type="button" disabled={disabled || loading} onClick={() => void refresh()}>
              {loading ? 'Loading coins…' : 'Refresh coins'}
            </Button>
            <p role="status" className="break-words text-muted">
              {selected.length} selected · {total.toString()} sats observed
              {fee !== '' &&
              /^[0-9]+$/.test(fee) &&
              Number(fee) >= 1 &&
              Number(fee) <= 100 &&
              selected.length > 0
                ? ` · estimated fee ${(BigInt(73 + 69 * selected.length) * BigInt(fee)).toString()} sats`
                : ''}
            </p>
            {loaded && coins.length === 0 && (
              <p className="text-faint">
                No unspent outputs were returned. Refresh after funding this Signet address.
              </p>
            )}
            <ul className="space-y-2">
              {coins.slice(0, shown).map((coin) => {
                const key = `${coin.txid}:${coin.vout}`;
                const checked = selected.includes(key);
                return (
                  <li key={key}>
                    <label className="flex min-h-11 items-start gap-2 rounded-sw-sm border border-edge p-2 text-muted">
                      <input
                        className="mt-1"
                        type="checkbox"
                        checked={checked}
                        disabled={
                          disabled ||
                          loading ||
                          !coin.status.confirmed ||
                          (!checked && selected.length >= 8)
                        }
                        onChange={() => {
                          const next = checked
                            ? selected.filter((k) => k !== key)
                            : [...selected, key];
                          setSelected(next);
                          update(manual, next, fee);
                        }}
                      />
                      <span className="min-w-0 flex-1">
                        <span className="block break-all">{key}</span>
                        <span className="block">
                          {coin.value.toString()} sats ·{' '}
                          {coin.status.confirmed
                            ? `confirmed${coin.status.block_height === undefined ? '' : ` at height ${coin.status.block_height}`}`
                            : 'unconfirmed · unavailable for selection'}
                        </span>
                      </span>
                    </label>
                  </li>
                );
              })}
            </ul>
            {coins.length > shown && (
              <Button type="button" onClick={() => setShown((n) => n + 100)}>
                Show next {Math.min(100, coins.length - shown)} coins
              </Button>
            )}
          </>
        )}
        {error && (
          <p role="alert" className="break-words text-danger">
            {error}
          </p>
        )}
        <p className="text-faint">
          The final proposal shows the validated fee and change. Dust change and insufficient
          selections are refused; manual selection never adds or substitutes an input.
        </p>
      </div>
    </details>
  );
}
