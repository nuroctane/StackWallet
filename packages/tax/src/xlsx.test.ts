import { describe, expect, it } from 'vitest';
import {
  buildXlsx,
  columnRef,
  excelSerial,
  sanitizeSheetNames,
  type WorkbookSpec,
} from './xlsx.js';
import { crc32, zipStore } from './zip.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

function readStoreZip(bytes: Uint8Array): Map<string, string> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const eocd = bytes.length - 22;
  expect(view.getUint32(eocd, true)).toBe(0x06054b50);
  const count = view.getUint16(eocd + 10, true);
  const cdSize = view.getUint32(eocd + 12, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  expect(cdOffset + cdSize).toBe(eocd);
  const files = new Map<string, string>();
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    expect(view.getUint32(p, true)).toBe(0x02014b50);
    expect(view.getUint16(p + 10, true)).toBe(0);
    const crc = view.getUint32(p + 16, true);
    const size = view.getUint32(p + 24, true);
    const nameLen = view.getUint16(p + 28, true);
    const local = view.getUint32(p + 42, true);
    const name = dec.decode(bytes.subarray(p + 46, p + 46 + nameLen));
    expect(view.getUint32(local, true)).toBe(0x04034b50);
    const localNameLen = view.getUint16(local + 26, true);
    const extraLen = view.getUint16(local + 28, true);
    const start = local + 30 + localNameLen + extraLen;
    const data = bytes.subarray(start, start + size);
    expect(crc32(data)).toBe(crc);
    files.set(name, dec.decode(data));
    p += 46 + nameLen;
  }
  return files;
}

const SPEC: WorkbookSpec = {
  title: 'Tax report <2024>',
  createdMs: Date.UTC(2024, 5, 1, 12, 0, 0),
  sheets: [
    {
      name: 'Disposals',
      columns: [
        { header: 'Date', format: 'date' },
        { header: 'Asset', format: 'text' },
        { header: 'Amount', format: 'decimal' },
        { header: 'Proceeds', format: 'money' },
        { header: 'Long term' },
      ],
      rows: [
        [
          { date: Date.UTC(2024, 0, 1) },
          'BTC & "friends" <x>',
          '0.123456789012345678',
          1234.5,
          true,
        ],
        [{ date: Date.UTC(2024, 0, 1, 12) }, 'ETH\u0001\uD800', -1, Number.NaN, false],
        [null, undefined, '', Infinity, null],
      ],
    },
    { name: 'disposals', columns: [{ header: 'X' }], rows: [], freezeHeader: false },
    {
      name: 'a/b\\c[d]:e*f?g',
      columns: [{ header: 'Y', width: 20 }],
      rows: [[1]],
      autoFilter: false,
    },
  ],
};

describe('crc32', () => {
  it('matches the standard check value', () => {
    expect(crc32(enc.encode('123456789'))).toBe(0xcbf43926);
    expect(crc32(new Uint8Array())).toBe(0);
  });
});

describe('zipStore', () => {
  it('writes local headers, central directory and EOCD', () => {
    const zip = zipStore([
      { name: 'a.txt', data: enc.encode('hello') },
      { name: 'dir/é.txt', data: enc.encode('world') },
    ]);
    expect(Array.from(zip.subarray(0, 4))).toEqual([0x50, 0x4b, 0x03, 0x04]);
    const view = new DataView(zip.buffer);
    expect(view.getUint16(6, true) & 0x0800).toBe(0x0800);
    expect(view.getUint16(10, true)).toBe(0);
    expect(view.getUint16(12, true)).toBe(0x21);
    const files = readStoreZip(zip);
    expect(files.size).toBe(2);
    expect(files.get('a.txt')).toBe('hello');
    expect(files.get('dir/é.txt')).toBe('world');
  });

  it('encodes the DOS timestamp from dateMs', () => {
    const zip = zipStore([{ name: 'a', data: new Uint8Array([1]) }], Date.UTC(2024, 0, 2, 3, 4, 6));
    const view = new DataView(zip.buffer);
    expect(view.getUint16(12, true)).toBe((44 << 9) | (1 << 5) | 2);
    expect(view.getUint16(10, true)).toBe((3 << 11) | (4 << 5) | 3);
  });
});

describe('helpers', () => {
  it('builds column refs', () => {
    expect(columnRef(0)).toBe('A');
    expect(columnRef(25)).toBe('Z');
    expect(columnRef(26)).toBe('AA');
    expect(columnRef(701)).toBe('ZZ');
    expect(columnRef(702)).toBe('AAA');
  });

  it('converts epoch ms to Excel serials', () => {
    expect(excelSerial(Date.UTC(2024, 0, 1))).toBe(45292);
    expect(excelSerial(Date.UTC(2024, 0, 1, 12))).toBe(45292.5);
  });

  it('sanitizes and dedupes sheet names', () => {
    expect(sanitizeSheetNames(['A', 'a', 'A', '', '[]', "'q'", 'History'])).toEqual([
      'A',
      'a 2',
      'A 3',
      'Sheet',
      'Sheet 2',
      'q',
      'History 2',
    ]);
    const long = 'x'.repeat(40);
    const [first, second] = sanitizeSheetNames([long, long]);
    expect(first).toBe('x'.repeat(31));
    expect(second).toBe(`${'x'.repeat(29)} 2`);
  });
});

describe('buildXlsx', () => {
  const files = readStoreZip(buildXlsx(SPEC));

  it('contains every required part', () => {
    expect([...files.keys()].sort()).toEqual(
      [
        '[Content_Types].xml',
        '_rels/.rels',
        'docProps/app.xml',
        'docProps/core.xml',
        'xl/_rels/workbook.xml.rels',
        'xl/styles.xml',
        'xl/workbook.xml',
        'xl/worksheets/sheet1.xml',
        'xl/worksheets/sheet2.xml',
        'xl/worksheets/sheet3.xml',
      ].sort(),
    );
    expect(files.has('xl/sharedStrings.xml')).toBe(false);
    expect(files.get('[Content_Types].xml')).toContain('/xl/worksheets/sheet3.xml');
  });

  it('writes core properties', () => {
    const core = files.get('docProps/core.xml')!;
    expect(core).toContain('<dc:title>Tax report &lt;2024&gt;</dc:title>');
    expect(core).toContain('>2024-06-01T12:00:00Z</dcterms:created>');
  });

  it('writes cells with correct types, escaping and styles', () => {
    const sheet = files.get('xl/worksheets/sheet1.xml')!;
    expect(sheet).toContain(
      '<c r="A1" s="1" t="inlineStr"><is><t xml:space="preserve">Date</t></is></c>',
    );
    expect(sheet).toContain('<c r="A2" s="7"><v>45292</v></c>');
    expect(sheet).toContain('<c r="A3" s="7"><v>45292.5</v></c>');
    expect(sheet).toContain(
      '<c r="B2" s="2" t="inlineStr"><is><t xml:space="preserve">BTC &amp; &quot;friends&quot; &lt;x&gt;</t></is></c>',
    );
    expect(sheet).toContain(
      '<c r="C2" s="4" t="inlineStr"><is><t xml:space="preserve">0.123456789012345678</t></is></c>',
    );
    expect(sheet).toContain('<c r="D2" s="5"><v>1234.5</v></c>');
    expect(sheet).toContain('<c r="E2" t="b"><v>1</v></c>');
    expect(sheet).toContain('<t xml:space="preserve">ETH</t>');
    expect(sheet).toContain('<c r="C3" s="4"><v>-1</v></c>');
    expect(sheet).not.toContain('r="D3"');
    expect(sheet).toContain('<row r="4"/>');
    expect(sheet).not.toContain('NaN');
    expect(sheet).not.toContain('Infinity');
  });

  it('orders worksheet elements per schema and adds pane, cols and autoFilter', () => {
    const sheet = files.get('xl/worksheets/sheet1.xml')!;
    expect(sheet).toContain('<dimension ref="A1:E4"/>');
    expect(sheet).toContain(
      '<sheetView tabSelected="1" workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>',
    );
    expect(sheet).toContain('<col min="1" max="1" width="8" customWidth="1"/>');
    expect(sheet).toContain('<col min="5" max="5" width="11" customWidth="1"/>');
    expect(sheet).toContain('<autoFilter ref="A1:E4"/>');
    const order = [
      '<dimension',
      '<sheetViews',
      '<sheetFormatPr',
      '<cols',
      '<sheetData',
      '<autoFilter',
    ];
    const positions = order.map((tag) => sheet.indexOf(tag));
    expect(positions.every((p) => p >= 0)).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  it('respects freezeHeader, autoFilter and widths on other sheets', () => {
    const second = files.get('xl/worksheets/sheet2.xml')!;
    expect(second).not.toContain('<pane');
    expect(second).not.toContain('tabSelected');
    expect(second).not.toContain('<autoFilter');
    const third = files.get('xl/worksheets/sheet3.xml')!;
    expect(third).not.toContain('<autoFilter');
    expect(third).toContain('<col min="1" max="1" width="20" customWidth="1"/>');
    expect(third).toContain('<c r="A2"><v>1</v></c>');
  });

  it('writes sanitized, deduplicated sheet names and the filter defined name', () => {
    const wb = files.get('xl/workbook.xml')!;
    expect(wb).toContain('<sheet name="Disposals" sheetId="1" r:id="rId1"/>');
    expect(wb).toContain('<sheet name="disposals 2" sheetId="2" r:id="rId2"/>');
    expect(wb).toContain('<sheet name="abcdefg" sheetId="3" r:id="rId3"/>');
    expect(wb).toContain(
      '<definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">&apos;Disposals&apos;!$A$1:$E$4</definedName>',
    );
    expect(files.get('xl/_rels/workbook.xml.rels')).toContain('Target="styles.xml"');
  });

  it('defines the expected number formats', () => {
    const styles = files.get('xl/styles.xml')!;
    expect(styles).toContain('<numFmt numFmtId="164" formatCode="#,##0.########"/>');
    expect(styles).toContain('<numFmt numFmtId="167" formatCode="yyyy-mm-dd hh:mm:ss"/>');
    expect(styles).toContain('<fgColor rgb="FFF2F2F2"/>');
    expect(styles).toContain('<cellXfs count="9">');
  });

  it('is deterministic', () => {
    expect(buildXlsx(SPEC)).toEqual(buildXlsx(SPEC));
    const noDate = { sheets: [{ name: 'S', columns: [{ header: 'h' }], rows: [] }] };
    expect(buildXlsx(noDate)).toEqual(buildXlsx(noDate));
    expect(readStoreZip(buildXlsx(noDate)).get('docProps/core.xml')).toContain(
      '1980-01-01T00:00:00Z',
    );
  });

  it('rejects empty workbooks', () => {
    expect(() => buildXlsx({ sheets: [] })).toThrow();
  });
});
