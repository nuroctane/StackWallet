import type { CellValue } from './xlsx.js';

export interface CsvOptions {
  delimiter?: ',' | ';' | '\t';
  bom?: boolean;
  /** Defaults to true. */
  neutralizeFormulas?: boolean;
}

const PLAIN_NUMBER = /^-?\d+(\.\d+)?$/;
const FORMULA_TRIGGER = /^[=+\-@\t\r]/;

/** Formats a number without exponent notation for |n| < 1e21. */
export function plainNumber(n: number): string {
  if (!Number.isFinite(n)) return '';
  if (Object.is(n, -0)) return '0';
  const s = String(n);
  const e = s.indexOf('e');
  if (e < 0 || Math.abs(n) >= 1e21) return s;
  const negative = s.startsWith('-');
  const mantissa = s.slice(negative ? 1 : 0, e);
  const exponent = Number(s.slice(e + 1));
  const dot = mantissa.indexOf('.');
  const intLen = dot < 0 ? mantissa.length : dot;
  const digits = mantissa.replace('.', '');
  const point = intLen + exponent;
  let body: string;
  if (point <= 0) body = `0.${'0'.repeat(-point)}${digits}`;
  else if (point >= digits.length) body = digits + '0'.repeat(point - digits.length);
  else body = `${digits.slice(0, point)}.${digits.slice(point)}`;
  return (negative ? '-' : '') + body;
}

function isoUtc(ms: number): string {
  if (!Number.isFinite(ms) || Math.abs(ms) > 8.64e15) return '';
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function rawText(value: CellValue, neutralize: boolean): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') {
    // Spreadsheet apps execute cells starting with these characters as formulas; negative
    // amounts are exempt so they still import as numbers.
    if (neutralize && FORMULA_TRIGGER.test(value) && !PLAIN_NUMBER.test(value)) return `'${value}`;
    return value;
  }
  if (typeof value === 'number') return plainNumber(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'object' && typeof value.date === 'number') return isoUtc(value.date);
  return '';
}

function quote(text: string, delimiter: string): string {
  const needs =
    text.includes(delimiter) ||
    text.includes('"') ||
    text.includes('\r') ||
    text.includes('\n') ||
    /^[ \t]|[ \t]$/.test(text);
  return needs ? `"${text.replace(/"/g, '""')}"` : text;
}

export function buildCsv(columns: string[], rows: CellValue[][], opts: CsvOptions = {}): string {
  const delimiter = opts.delimiter ?? ',';
  const neutralize = opts.neutralizeFormulas ?? true;
  const line = (cells: readonly CellValue[]): string =>
    cells.map((c) => quote(rawText(c, neutralize), delimiter)).join(delimiter) + '\r\n';
  let out = opts.bom ? '\uFEFF' : '';
  out += line(columns);
  for (const row of rows) out += line(row);
  return out;
}
