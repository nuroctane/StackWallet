import { describe, expect, it } from 'vitest';
import { buildCsv, plainNumber } from './csv.js';

describe('buildCsv', () => {
  it('uses CRLF and RFC 4180 quoting', () => {
    const csv = buildCsv(
      ['a', 'b'],
      [
        ['x,y', 'say "hi"'],
        ['line\nbreak', ' padded'],
        ['cr\r', 'plain'],
      ],
    );
    expect(csv).toBe('a,b\r\n"x,y","say ""hi"""\r\n"line\nbreak"," padded"\r\n"cr\r",plain\r\n');
  });

  it('formats dates, booleans and empties', () => {
    const csv = buildCsv(
      ['d', 't', 'f', 'n', 'u', 'nan'],
      [[{ date: Date.UTC(2024, 0, 1, 2, 3, 4, 567) }, true, false, null, undefined, Number.NaN]],
    );
    expect(csv).toBe('d,t,f,n,u,nan\r\n2024-01-01T02:03:04Z,true,false,,,\r\n');
  });

  it('neutralizes formula-like strings but keeps negative numeric strings', () => {
    const csv = buildCsv(
      ['v'],
      [['=SUM(A1)'], ['+1+2'], ['-cmd'], ['@x'], ['\tx'], ['\rx'], ['-12.5'], ['-3'], ['1.0']],
    );
    expect(csv.split('\r\n')).toEqual([
      'v',
      "'=SUM(A1)",
      "'+1+2",
      "'-cmd",
      "'@x",
      "'\tx",
      `"'\rx"`,
      '-12.5',
      '-3',
      '1.0',
      '',
    ]);
  });

  it('can disable formula neutralization', () => {
    expect(buildCsv(['v'], [['=1+1']], { neutralizeFormulas: false })).toBe('v\r\n=1+1\r\n');
  });

  it('does not neutralize numbers', () => {
    expect(buildCsv(['v'], [[-5]])).toBe('v\r\n-5\r\n');
  });

  it('expands exponent notation', () => {
    expect(buildCsv(['v'], [[1e-7], [-2.5e-8], [123456789012345680000]])).toBe(
      'v\r\n0.0000001\r\n-0.000000025\r\n123456789012345680000\r\n',
    );
  });

  it('adds a BOM and supports other delimiters', () => {
    const csv = buildCsv(['a', 'b'], [['1;2', 'x,y']], { bom: true, delimiter: ';' });
    expect(csv.charCodeAt(0)).toBe(0xfeff);
    expect(csv.slice(1)).toBe('a;b\r\n"1;2";x,y\r\n');
    expect(buildCsv(['a', 'b'], [['x\ty', 'z']], { delimiter: '\t' })).toBe(
      'a\tb\r\n"x\ty"\tz\r\n',
    );
  });
});

describe('plainNumber', () => {
  it('handles edge cases', () => {
    expect(plainNumber(0)).toBe('0');
    expect(plainNumber(-0)).toBe('0');
    expect(plainNumber(1.5e-10)).toBe('0.00000000015');
    expect(plainNumber(5e-324)).toBe(`0.${'0'.repeat(323)}5`);
    expect(plainNumber(1e21)).toBe('1e+21');
    expect(plainNumber(Infinity)).toBe('');
  });
});
