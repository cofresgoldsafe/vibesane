const HORIZONTAL_BOX_CHARS = new Set<string>([
  '\u2500', // ─
  '\u2501', // ━
  '\u2504', // ┄
  '\u2505', // ┅
  '\u2508', // ┈
  '\u2509', // ┉
  '\u254C', // ╌
  '\u254D', // ╍
  '\u2550', // ═
  '\u2574', // ╴
  '\u2576', // ╶
  '\u2578', // ╸
  '\u257A', // ╺
]);

const VERTICAL_BOX_CHARS = new Set<string>([
  '\u2502', // │
  '\u2503', // ┃
  '\u2506', // ┆
  '\u2507', // ┇
  '\u250A', // ┊
  '\u250B', // ┋
  '\u254E', // ╎
  '\u254F', // ╏
  '\u2551', // ║
  '\u2575', // ╵
  '\u2577', // ╷
  '\u2579', // ╹
  '\u257B', // ╻
]);

export function toAsciiSafe(value: string): string {
  if (!value) {
    return '';
  }

  return value
    .replace(/\r\n?/g, '\n')
    .replace(/\u00D7/g, 'x')
    .replace(/\u00B7/g, ':')
    .replace(/[\u2014\u2013]/g, '-')
    .replace(/\u2026/g, '...')
    .replace(/\u2022/g, '*')
    .replace(/[\u2500-\u259F]/g, (ch) => {
      if (HORIZONTAL_BOX_CHARS.has(ch)) {
        return '-';
      }
      if (VERTICAL_BOX_CHARS.has(ch)) {
        return '|';
      }
      return '+';
    });
}
