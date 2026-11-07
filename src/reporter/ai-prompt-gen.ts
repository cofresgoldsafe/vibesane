import {
  stripViteTimestampQuery,
  type SanityIssue,
} from '../scanner/security-scan.js';
import { toAsciiSafe } from '../text/ascii.js';

export { stripViteTimestampQuery };

export const AI_PROMPT_HEADER =
  'AI FIX PROMPT (copy & paste into Cursor / Claude Code / Gemini CLI):';

export const SECRET_LEAK_INSTRUCTION =
  'Move this key to a server-only environment variable (never NEXT_PUBLIC_ / VITE_) and rotate it if it was ever committed or deployed.';

export const CODE_ERROR_INSTRUCTION =
  'Fix only the error pointed out above; do not refactor unrelated code.';

export const MAX_PROMPT_ERRORS = 10;

const ANSI_ESCAPE_RE = /\x1b\[[0-9;]*m/g;

export type AiPromptIssue = SanityIssue & {
  codeFrame?: string;
};

export interface AiPromptInput {
  ok: boolean;
  port: number | null;
  url?: string;
  issues: readonly AiPromptIssue[];
}

export function stripAnsiCodes(value: string): string {
  if (!value) {
    return '';
  }
  return value.replace(ANSI_ESCAPE_RE, '');
}

export function detailContainsRoute(detail: string, route: string): boolean {
  if (!detail || !route) {
    return false;
  }
  const escaped = route.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:^|\\s)${escaped}(?=$|\\s|:|\\)|,)`).test(detail);
}

function formatIndentedCodeFrame(rawFrame: string, maxLines = 10): string {
  const clean = toAsciiSafe(stripAnsiCodes(rawFrame)).replace(/\r\n/g, '\n').trimEnd();
  if (!clean) {
    return '';
  }
  const lines = clean
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line, idx, arr) => !(line === '' && (idx === 0 || idx === arr.length - 1)))
    .slice(0, maxLines);

  if (lines.length === 0) {
    return '';
  }

  return lines.map((line) => `   ${line}`).join('\n');
}

export function generateAiFixPrompt(input: AiPromptInput): string | null {
  if (input.port === null || !Array.isArray(input.issues) || input.issues.length === 0) {
    return null;
  }

  const errorIssues = input.issues.filter((issue) => issue.severity === 'error');
  if (errorIssues.length === 0) {
    return null;
  }

  interface NormalizedPromptError {
    kind: AiPromptIssue['kind'];
    route: string;
    detail: string;
    codeFrame?: string;
  }

  const uniqueErrors: NormalizedPromptError[] = [];
  const seenKeys = new Set<string>();

  for (const issue of errorIssues) {
    const cleanRoute =
      toAsciiSafe(stripViteTimestampQuery(stripAnsiCodes(issue.route).trim())) || '/';
    const cleanDetail = toAsciiSafe(
      stripViteTimestampQuery(stripAnsiCodes(issue.detail).trim()),
    );
    const dedupeKey = `${issue.kind}::${cleanRoute}::${cleanDetail}`;
    if (seenKeys.has(dedupeKey)) {
      continue;
    }
    seenKeys.add(dedupeKey);

    const formattedFrame = issue.codeFrame
      ? formatIndentedCodeFrame(issue.codeFrame, 10)
      : '';

    uniqueErrors.push({
      kind: issue.kind,
      route: cleanRoute,
      detail: cleanDetail,
      ...(formattedFrame ? { codeFrame: formattedFrame } : {}),
    });
  }

  if (uniqueErrors.length === 0) {
    return null;
  }

  const shownErrors = uniqueErrors.slice(0, MAX_PROMPT_ERRORS);
  const remaining = uniqueErrors.length - shownErrors.length;

  const lines: string[] = [AI_PROMPT_HEADER];
  if (typeof input.url === 'string' && input.url.trim().length > 0) {
    lines.push(`Target: ${toAsciiSafe(stripAnsiCodes(input.url.trim()))}`);
  }

  shownErrors.forEach((err, index) => {
    if (detailContainsRoute(err.detail, err.route)) {
      lines.push(`${index + 1}. [${err.kind}] ${err.detail}`);
    } else {
      lines.push(`${index + 1}. [${err.kind}] ${err.route} - ${err.detail}`);
    }
    if (err.codeFrame) {
      lines.push(err.codeFrame);
    }
  });

  if (remaining > 0) {
    lines.push(`...and ${remaining} more`);
  }

  const hasSecretLeak = uniqueErrors.some((err) => err.kind === 'secret_leak');
  const hasCodeError = uniqueErrors.some(
    (err) =>
      err.kind === 'http_error' ||
      err.kind === 'masked_error' ||
      err.kind === 'syntax_error',
  );

  if (hasSecretLeak && hasCodeError) {
    lines.push(`Instruction (secrets): ${SECRET_LEAK_INSTRUCTION}`);
    lines.push(`Instruction (code): ${CODE_ERROR_INSTRUCTION}`);
  } else if (hasSecretLeak) {
    lines.push(`Instruction: ${SECRET_LEAK_INSTRUCTION}`);
  } else if (hasCodeError) {
    lines.push(`Instruction: ${CODE_ERROR_INSTRUCTION}`);
  }

  return toAsciiSafe(stripAnsiCodes(lines.join('\n')));
}
