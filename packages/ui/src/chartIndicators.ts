import type { Point } from './CanvasChart.js';

/**
 * Technical indicators as pure functions over close-price arrays. Every
 * function returns an array aligned with its input, with `null` during the
 * warmup period so the renderer can start a series late instead of drawing
 * a fake value. No mutation, no allocation beyond the result.
 */

export type NullableSeries = (number | null)[];

/** Simple moving average; null until `period` samples exist. */
export function sma(values: readonly number[], period: number): NullableSeries {
  const out: NullableSeries = new Array<number | null>(values.length).fill(null);
  if (period < 1 || values.length < period) return out;
  let sum = 0;
  for (let i = 0; i < values.length; i++) {
    sum += values[i] as number;
    if (i >= period) sum -= values[i - period] as number;
    if (i >= period - 1) out[i] = sum / period;
  }
  return out;
}

/** Exponential moving average, seeded with the SMA of the first `period` samples. */
export function ema(values: readonly number[], period: number): NullableSeries {
  const out: NullableSeries = new Array<number | null>(values.length).fill(null);
  if (period < 1 || values.length < period) return out;
  const k = 2 / (period + 1);
  let seed = 0;
  for (let i = 0; i < period; i++) seed += values[i] as number;
  let prev = seed / period;
  out[period - 1] = prev;
  for (let i = period; i < values.length; i++) {
    prev = (values[i] as number) * k + prev * (1 - k);
    out[i] = prev;
  }
  return out;
}

export interface BollingerBand {
  mid: NullableSeries;
  upper: NullableSeries;
  lower: NullableSeries;
}

/** Bollinger Bands: SMA ± `mult` population standard deviations over `period`. */
export function bollinger(values: readonly number[], period: number, mult = 2): BollingerBand {
  const n = values.length;
  const mid: NullableSeries = new Array<number | null>(n).fill(null);
  const upper: NullableSeries = new Array<number | null>(n).fill(null);
  const lower: NullableSeries = new Array<number | null>(n).fill(null);
  if (period < 2 || n < period) return { mid, upper, lower };
  let sum = 0;
  let sumSq = 0;
  for (let i = 0; i < n; i++) {
    const v = values[i] as number;
    sum += v;
    sumSq += v * v;
    if (i >= period) {
      const old = values[i - period] as number;
      sum -= old;
      sumSq -= old * old;
    }
    if (i >= period - 1) {
      const mean = sum / period;
      // Float error can push the variance just below zero on flat windows.
      const variance = Math.max(0, sumSq / period - mean * mean);
      const sd = Math.sqrt(variance);
      mid[i] = mean;
      upper[i] = mean + mult * sd;
      lower[i] = mean - mult * sd;
    }
  }
  return { mid, upper, lower };
}

/** Wilder's RSI over closes; null until `period` gains/losses exist. */
export function rsi(closes: readonly number[], period = 14): NullableSeries {
  const n = closes.length;
  const out: NullableSeries = new Array<number | null>(n).fill(null);
  if (period < 1 || n <= period) return out;
  let gain = 0;
  let loss = 0;
  for (let i = 1; i <= period; i++) {
    const d = (closes[i] as number) - (closes[i - 1] as number);
    if (d > 0) gain += d;
    else loss -= d;
  }
  let avgGain = gain / period;
  let avgLoss = loss / period;
  out[period] = avgLoss === 0 ? 100 : 100 - 100 / (1 + avgGain / avgLoss);
  for (let i = period + 1; i < n; i++) {
    const d = (closes[i] as number) - (closes[i - 1] as number);
    avgGain = (avgGain * (period - 1) + Math.max(0, d)) / period;
    avgLoss = (avgLoss * (period - 1) + Math.max(0, -d)) / period;
    out[i] = avgLoss === 0 ? 100 : 100 - 100 / (1 + avgGain / avgLoss);
  }
  return out;
}

export interface MacdResult {
  macd: NullableSeries;
  signal: NullableSeries;
  histogram: NullableSeries;
}

/** MACD: fast EMA − slow EMA, with a signal EMA of the MACD line. */
export function macd(
  closes: readonly number[],
  fast = 12,
  slow = 26,
  signalPeriod = 9,
): MacdResult {
  const n = closes.length;
  const line: NullableSeries = new Array<number | null>(n).fill(null);
  const signal: NullableSeries = new Array<number | null>(n).fill(null);
  const histogram: NullableSeries = new Array<number | null>(n).fill(null);
  if (n < slow + signalPeriod || fast >= slow) return { macd: line, signal, histogram };
  const fastE = ema(closes, fast);
  const slowE = ema(closes, slow);
  const raw: number[] = [];
  const idx: number[] = [];
  for (let i = 0; i < n; i++) {
    const f = fastE[i];
    const s = slowE[i];
    if (f != null && s != null) {
      line[i] = f - s;
      raw.push(f - s);
      idx.push(i);
    }
  }
  const sig = ema(raw, signalPeriod);
  for (let j = 0; j < idx.length; j++) {
    const s = sig[j];
    if (s != null) {
      const i = idx[j] as number;
      signal[i] = s;
      histogram[i] = (line[i] as number) - s;
    }
  }
  return { macd: line, signal, histogram };
}

/** Heikin Ashi candles from OHLC points; the first open is the midpoint of candle one. */
export function heikinAshi(points: readonly Point[]): Point[] {
  const out: Point[] = [];
  let prevO: number | null = null;
  let prevC: number | null = null;
  for (const p of points) {
    const o = p.o ?? p.v;
    const c = p.v;
    const h = p.h ?? Math.max(o, c);
    const l = p.l ?? Math.min(o, c);
    const hc = (o + h + l + c) / 4;
    const ho: number = prevO === null || prevC === null ? (o + c) / 2 : (prevO + prevC) / 2;
    out.push({
      t: p.t,
      v: hc,
      o: ho,
      h: Math.max(h, ho, hc),
      l: Math.min(l, ho, hc),
    });
    prevO = ho;
    prevC = hc;
  }
  return out;
}

/** Attach indicator values back onto timestamps; warmup nulls drop out. */
export function toPoints(times: readonly number[], values: NullableSeries): Point[] {
  const out: Point[] = [];
  for (let i = 0; i < times.length; i++) {
    const v = values[i];
    if (v !== null && v !== undefined && Number.isFinite(v)) {
      out.push({ t: times[i] as number, v });
    }
  }
  return out;
}
