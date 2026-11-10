import { toAsciiSafe } from '../text/ascii.js';
import type { SanityIssue } from '../scanner/security-scan.js';

export const V8_STACK_FRAME_RE =
  /(?:^|\n)[ \t]*at (?:(?:async|new) )?(?:[^\s()]+(?: \[as [^\]\s]+\])? \()?(?:\/|[A-Za-z]:[\\/])[^\r\n:()]+:\d+:\d+/;

export const PYTHON_TRACEBACK_RE =
  /Traceback \(most recent call last\):[\s\S]{0,500}?\n[ \t]*File\s+["'][^"'\r\n]+["'],\s+line\s+\d+/;

export const DATABASE_ERROR_RE =
  /PrismaClient(?:Known|Unknown|Initialization|Rust)RequestError|Invalid `prisma\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\(\)` invocation|syntax error at or near\b|relation "[^"]+" does not exist|column "[^"]+" does not exist|Table '[^']+' doesn't exist|ORA-\d{5}\b/i;

function cleanSnippet(raw: string, maxLen = 120): string {
  const singleLine = raw.replace(/[\r\n\t]+/g, ' ').trim();
  const safe = toAsciiSafe(singleLine);
  if (safe.length <= maxLen) {
    return safe;
  }
  return `${safe.slice(0, maxLen - 3)}...`;
}

export function detectStackTraceLeak(
  body: string,
  statusCode?: number,
  route = '/',
): SanityIssue | null {
  // Escopo estrito: somente respostas com status >= 400
  if (statusCode === undefined || statusCode < 400) {
    return null;
  }

  if (!body || body.length === 0) {
    return null;
  }

  // Descompacta quebras de linha literais em JSON para garantir detecção em payloads serializados
  const normalized = body.replace(/\\n/g, '\n');

  const v8Match = V8_STACK_FRAME_RE.exec(normalized);
  if (v8Match) {
    const snippet = cleanSnippet(v8Match[0]);
    return {
      kind: 'stack_trace_leak',
      severity: 'error',
      route,
      statusCode,
      detail: `Raw runtime error stack trace detected in response (${snippet}); internal file paths or database queries are exposed`,
    };
  }

  const pyMatch = PYTHON_TRACEBACK_RE.exec(normalized);
  if (pyMatch) {
    const snippet = cleanSnippet(pyMatch[0]);
    return {
      kind: 'stack_trace_leak',
      severity: 'error',
      route,
      statusCode,
      detail: `Raw runtime error stack trace detected in response (${snippet}); internal file paths or database queries are exposed`,
    };
  }

  const dbMatch = DATABASE_ERROR_RE.exec(normalized);
  if (dbMatch) {
    const snippet = cleanSnippet(dbMatch[0]);
    return {
      kind: 'stack_trace_leak',
      severity: 'error',
      route,
      statusCode,
      detail: `Raw runtime error stack trace detected in response (${snippet}); internal file paths or database queries are exposed`,
    };
  }

  return null;
}
