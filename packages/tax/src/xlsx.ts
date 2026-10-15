import { zipStore, type ZipEntry } from './zip.js';

export type CellValue = string | number | boolean | null | undefined | { date: number };

export type ColumnFormat =
  | 'text'
  | 'integer'
  | 'decimal'
  | 'money'
  | 'percent'
  | 'date'
  | 'datetime';

export interface SheetColumn {
  header: string;
  /** Width in characters. Defaults to the header length clamped to 8..60. */
  width?: number;
  format?: ColumnFormat;
}

export interface SheetSpec {
  name: string;
  columns: SheetColumn[];
  rows: CellValue[][];
  /** Defaults to true. */
  freezeHeader?: boolean;
  /** Defaults to true. */
  autoFilter?: boolean;
}

export interface WorkbookSpec {
  sheets: SheetSpec[];
  title?: string;
  createdMs?: number;
}

const MAX_CELL_CHARS = 32767;
const MAX_SHEET_NAME = 31;
const MS_PER_DAY = 86_400_000;
// Days between Excel's day zero (1899-12-30, which absorbs the 1900 leap-year bug) and 1970-01-01.
const EXCEL_EPOCH_OFFSET_DAYS = 25569;

const STYLE_DEFAULT = 0;
const STYLE_HEADER = 1;
const FORMAT_STYLE: Record<ColumnFormat, number> = {
  text: 2,
  integer: 3,
  decimal: 4,
  money: 5,
  percent: 6,
  date: 7,
  datetime: 8,
};

const XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';
const NS_MAIN = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
const NS_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
const NS_PKG_REL = 'http://schemas.openxmlformats.org/package/2006/relationships';

export function sanitizeXmlText(input: string): string {
  let out = '';
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = input.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += input[i]! + input[i + 1]!;
        i++;
      }
      continue;
    }
    if (c >= 0xdc00 && c <= 0xdfff) continue;
    if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) continue;
    if (c === 0xfffe || c === 0xffff) continue;
    out += input[i]!;
  }
  return out;
}

export function escapeXml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function xmlText(input: string): string {
  return escapeXml(sanitizeXmlText(input));
}

function capCellText(input: string): string {
  if (input.length <= MAX_CELL_CHARS) return input;
  let cut = input.slice(0, MAX_CELL_CHARS);
  const last = cut.charCodeAt(cut.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) cut = cut.slice(0, -1);
  return cut;
}

export function columnRef(index: number): string {
  let n = index + 1;
  let ref = '';
  while (n > 0) {
    const rem = (n - 1) % 26;
    ref = String.fromCharCode(65 + rem) + ref;
    n = Math.floor((n - 1) / 26);
  }
  return ref;
}

export function excelSerial(epochMs: number): number {
  return epochMs / MS_PER_DAY + EXCEL_EPOCH_OFFSET_DAYS;
}

function isDateCell(v: unknown): v is { date: number } {
  return typeof v === 'object' && v !== null && typeof (v as { date?: unknown }).date === 'number';
}

const RESERVED_SHEET_NAMES = new Set(['history']);

export function sanitizeSheetNames(names: string[]): string[] {
  const used = new Set<string>(RESERVED_SHEET_NAMES);
  return names.map((raw) => {
    let base = sanitizeXmlText(raw)
      .replace(/[[\]:*?/\\]/g, '')
      .replace(/[\r\n\t]/g, ' ')
      .trim()
      // Excel rejects sheet names that begin or end with an apostrophe.
      .replace(/^'+|'+$/g, '')
      .trim();
    if (base.length === 0) base = 'Sheet';
    base = trimToLength(base, MAX_SHEET_NAME);
    let candidate = base;
    for (let n = 2; used.has(candidate.toLowerCase()); n++) {
      const suffix = ` ${n}`;
      candidate = trimToLength(base, MAX_SHEET_NAME - suffix.length).trimEnd() + suffix;
    }
    used.add(candidate.toLowerCase());
    return candidate;
  });
}

function trimToLength(s: string, max: number): string {
  if (s.length <= max) return s;
  let cut = s.slice(0, max);
  const last = cut.charCodeAt(cut.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) cut = cut.slice(0, -1);
  return cut;
}

function columnWidth(col: SheetColumn): number {
  const w =
    col.width !== undefined && Number.isFinite(col.width)
      ? col.width
      : Math.min(60, Math.max(8, col.header.length + 2));
  return Math.min(255, Math.max(1, w));
}

function numberText(n: number): string {
  return Object.is(n, -0) ? '0' : String(n);
}

function cellXml(ref: string, value: CellValue, format: ColumnFormat | undefined): string {
  const colStyle = format ? FORMAT_STYLE[format] : STYLE_DEFAULT;
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') {
    if (value.length === 0) return '';
    const s = colStyle === STYLE_DEFAULT ? '' : ` s="${colStyle}"`;
    return `<c r="${ref}"${s} t="inlineStr"><is><t xml:space="preserve">${xmlText(capCellText(value))}</t></is></c>`;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return '';
    const s = colStyle === STYLE_DEFAULT ? '' : ` s="${colStyle}"`;
    return `<c r="${ref}"${s}><v>${numberText(value)}</v></c>`;
  }
  if (typeof value === 'boolean') {
    return `<c r="${ref}" t="b"><v>${value ? 1 : 0}</v></c>`;
  }
  if (isDateCell(value)) {
    if (!Number.isFinite(value.date)) return '';
    const serial = excelSerial(value.date);
    // Excel cannot display serials before its day zero.
    if (serial < 0) return '';
    const style = format === 'date' ? FORMAT_STYLE.date : FORMAT_STYLE.datetime;
    return `<c r="${ref}" s="${style}"><v>${numberText(serial)}</v></c>`;
  }
  return '';
}

function sheetXml(sheet: SheetSpec, index: number): string {
  const freeze = sheet.freezeHeader ?? true;
  const filter = sheet.autoFilter ?? true;
  const columnCount = sheet.columns.length;
  let width = columnCount;
  for (const row of sheet.rows) width = Math.max(width, row.length);
  const lastRow = sheet.rows.length + 1;
  const dimension = width > 0 ? `A1:${columnRef(width - 1)}${lastRow}` : 'A1';

  const parts: string[] = [XML_DECL, `<worksheet xmlns="${NS_MAIN}" xmlns:r="${NS_REL}">`];
  parts.push(`<dimension ref="${dimension}"/>`);
  const selected = index === 0 ? ' tabSelected="1"' : '';
  if (freeze) {
    parts.push(
      `<sheetViews><sheetView${selected} workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A2" sqref="A2"/></sheetView></sheetViews>`,
    );
  } else {
    parts.push(`<sheetViews><sheetView${selected} workbookViewId="0"/></sheetViews>`);
  }
  parts.push('<sheetFormatPr defaultRowHeight="15"/>');
  if (columnCount > 0) {
    parts.push('<cols>');
    sheet.columns.forEach((col, i) => {
      const n = i + 1;
      parts.push(`<col min="${n}" max="${n}" width="${columnWidth(col)}" customWidth="1"/>`);
    });
    parts.push('</cols>');
  }

  parts.push('<sheetData>');
  if (columnCount > 0) {
    parts.push('<row r="1">');
    sheet.columns.forEach((col, i) => {
      const text = capCellText(col.header);
      parts.push(
        `<c r="${columnRef(i)}1" s="${STYLE_HEADER}" t="inlineStr"><is><t xml:space="preserve">${xmlText(text)}</t></is></c>`,
      );
    });
    parts.push('</row>');
  }
  sheet.rows.forEach((row, r) => {
    const rowNum = r + 2;
    let cells = '';
    row.forEach((value, c) => {
      cells += cellXml(`${columnRef(c)}${rowNum}`, value, sheet.columns[c]?.format);
    });
    parts.push(cells.length > 0 ? `<row r="${rowNum}">${cells}</row>` : `<row r="${rowNum}"/>`);
  });
  parts.push('</sheetData>');

  if (filter && sheet.rows.length > 0 && columnCount > 0) {
    parts.push(`<autoFilter ref="${filterRange(sheet)}"/>`);
  }
  parts.push('</worksheet>');
  return parts.join('');
}

function filterRange(sheet: SheetSpec): string {
  return `A1:${columnRef(sheet.columns.length - 1)}${sheet.rows.length + 1}`;
}

function absoluteRange(range: string): string {
  return range.replace(/([A-Z]+)(\d+)/g, '$$$1$$$2');
}

function quoteSheetName(name: string): string {
  return `'${name.replace(/'/g, "''")}'`;
}

const STYLES_XML =
  XML_DECL +
  `<styleSheet xmlns="${NS_MAIN}">` +
  '<numFmts count="4">' +
  '<numFmt numFmtId="164" formatCode="#,##0.########"/>' +
  '<numFmt numFmtId="165" formatCode="#,##0.00"/>' +
  '<numFmt numFmtId="166" formatCode="yyyy-mm-dd"/>' +
  '<numFmt numFmtId="167" formatCode="yyyy-mm-dd hh:mm:ss"/>' +
  '</numFmts>' +
  '<fonts count="2">' +
  '<font><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/><scheme val="minor"/></font>' +
  '<font><b/><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/><scheme val="minor"/></font>' +
  '</fonts>' +
  '<fills count="3">' +
  '<fill><patternFill patternType="none"/></fill>' +
  '<fill><patternFill patternType="gray125"/></fill>' +
  '<fill><patternFill patternType="solid"><fgColor rgb="FFF2F2F2"/><bgColor indexed="64"/></patternFill></fill>' +
  '</fills>' +
  '<borders count="2">' +
  '<border><left/><right/><top/><bottom/><diagonal/></border>' +
  '<border><left/><right/><top/><bottom style="thin"><color auto="1"/></bottom><diagonal/></border>' +
  '</borders>' +
  '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
  '<cellXfs count="9">' +
  '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
  '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>' +
  '<xf numFmtId="49" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>' +
  '<xf numFmtId="1" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>' +
  '<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>' +
  '<xf numFmtId="165" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>' +
  '<xf numFmtId="10" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>' +
  '<xf numFmtId="166" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>' +
  '<xf numFmtId="167" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>' +
  '</cellXfs>' +
  '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
  '<dxfs count="0"/><tableStyles count="0"/>' +
  '</styleSheet>';

const DEFAULT_CREATED = '1980-01-01T00:00:00Z';

function isoSeconds(ms: number | undefined): string {
  if (ms === undefined || !Number.isFinite(ms) || Math.abs(ms) > 8.64e15) return DEFAULT_CREATED;
  const year = new Date(ms).getUTCFullYear();
  if (year < 0 || year > 9999) return DEFAULT_CREATED;
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function buildXlsx(spec: WorkbookSpec): Uint8Array {
  if (spec.sheets.length === 0) throw new Error('xlsx: workbook needs at least one sheet');
  const names = sanitizeSheetNames(spec.sheets.map((s) => s.name));
  const created = isoSeconds(spec.createdMs);
  const enc = new TextEncoder();

  const contentTypes =
    XML_DECL +
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
    '<Default Extension="xml" ContentType="application/xml"/>' +
    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
    spec.sheets
      .map(
        (_, i) =>
          `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`,
      )
      .join('') +
    '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
    '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>' +
    '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>' +
    '</Types>';

  const rootRels =
    XML_DECL +
    `<Relationships xmlns="${NS_PKG_REL}">` +
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>' +
    '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>' +
    '</Relationships>';

  const title = spec.title !== undefined ? `<dc:title>${xmlText(spec.title)}</dc:title>` : '';
  const core =
    XML_DECL +
    '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' +
    title +
    '<dc:creator>StackWallet</dc:creator>' +
    `<dcterms:created xsi:type="dcterms:W3CDTF">${created}</dcterms:created>` +
    `<dcterms:modified xsi:type="dcterms:W3CDTF">${created}</dcterms:modified>` +
    '</cp:coreProperties>';

  const app =
    XML_DECL +
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">' +
    '<Application>StackWallet</Application>' +
    '</Properties>';

  const definedNames = spec.sheets
    .map((sheet, i) => {
      const filter = sheet.autoFilter ?? true;
      if (!filter || sheet.rows.length === 0 || sheet.columns.length === 0) return '';
      const ref = `${quoteSheetName(names[i]!)}!${absoluteRange(filterRange(sheet))}`;
      return `<definedName name="_xlnm._FilterDatabase" localSheetId="${i}" hidden="1">${escapeXml(ref)}</definedName>`;
    })
    .join('');

  const workbook =
    XML_DECL +
    `<workbook xmlns="${NS_MAIN}" xmlns:r="${NS_REL}">` +
    '<bookViews><workbookView activeTab="0"/></bookViews>' +
    '<sheets>' +
    names
      .map((n, i) => `<sheet name="${escapeXml(n)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`)
      .join('') +
    '</sheets>' +
    (definedNames.length > 0 ? `<definedNames>${definedNames}</definedNames>` : '') +
    '</workbook>';

  const workbookRels =
    XML_DECL +
    `<Relationships xmlns="${NS_PKG_REL}">` +
    spec.sheets
      .map(
        (_, i) =>
          `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`,
      )
      .join('') +
    `<Relationship Id="rId${spec.sheets.length + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
    '</Relationships>';

  const files: ZipEntry[] = [
    { name: '[Content_Types].xml', data: enc.encode(contentTypes) },
    { name: '_rels/.rels', data: enc.encode(rootRels) },
    { name: 'docProps/core.xml', data: enc.encode(core) },
    { name: 'docProps/app.xml', data: enc.encode(app) },
    { name: 'xl/workbook.xml', data: enc.encode(workbook) },
    { name: 'xl/_rels/workbook.xml.rels', data: enc.encode(workbookRels) },
    { name: 'xl/styles.xml', data: enc.encode(STYLES_XML) },
    ...spec.sheets.map((sheet, i) => ({
      name: `xl/worksheets/sheet${i + 1}.xml`,
      data: enc.encode(sheetXml(sheet, i)),
    })),
  ];
  return zipStore(files, spec.createdMs);
}
