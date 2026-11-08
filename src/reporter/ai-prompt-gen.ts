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

export const SERVER_ENV_IN_CLIENT_INSTRUCTION =
  'Move code that accesses server environment variables to a server-only file (in Next.js, add import "server-only") and do not import that file into browser/client components.';

export const EXPOSED_FILE_INSTRUCTION =
  "Do not serve the project root as static files: serve only a dedicated public folder (e.g. express.static('public')), and rotate every key that was in the exposed file.";

export const INSECURE_CORS_INSTRUCTION =
  'Do not reflect the request Origin when credentials are allowed: configure an explicit allowlist of trusted origins in your CORS settings (e.g. cors({ origin: [ ... trusted origins ... ], credentials: true }) in Express, or allow_origins=[ ... ] instead of * or .* in FastAPI).';

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
  const hasServerEnvInClient = uniqueErrors.some(
    (err) => err.kind === 'server_env_in_client',
  );
  const hasExposedFile = uniqueErrors.some((err) => err.kind === 'exposed_file');
  const hasInsecureCors = uniqueErrors.some((err) => err.kind === 'insecure_cors');
  const hasCodeError = uniqueErrors.some(
    (err) =>
      err.kind === 'http_error' ||
      err.kind === 'masked_error' ||
      err.kind === 'syntax_error',
  );

  const activeCategoriesCount =
    (hasSecretLeak ? 1 : 0) +
    (hasServerEnvInClient ? 1 : 0) +
    (hasExposedFile ? 1 : 0) +
    (hasInsecureCors ? 1 : 0) +
    (hasCodeError ? 1 : 0);

  if (activeCategoriesCount === 1) {
    if (hasSecretLeak) {
      lines.push(`Instruction: ${SECRET_LEAK_INSTRUCTION}`);
    } else if (hasServerEnvInClient) {
      lines.push(`Instruction: ${SERVER_ENV_IN_CLIENT_INSTRUCTION}`);
    } else if (hasExposedFile) {
      lines.push(`Instruction: ${EXPOSED_FILE_INSTRUCTION}`);
    } else if (hasInsecureCors) {
      lines.push(`Instruction: ${INSECURE_CORS_INSTRUCTION}`);
    } else if (hasCodeError) {
      lines.push(`Instruction: ${CODE_ERROR_INSTRUCTION}`);
    }
  } else if (activeCategoriesCount > 1) {
    if (hasSecretLeak) {
      lines.push(`Instruction (secrets): ${SECRET_LEAK_INSTRUCTION}`);
    }
    if (hasServerEnvInClient) {
      lines.push(
        `Instruction (server env in client): ${SERVER_ENV_IN_CLIENT_INSTRUCTION}`,
      );
    }
    if (hasExposedFile) {
      lines.push(`Instruction (exposed files): ${EXPOSED_FILE_INSTRUCTION}`);
    }
    if (hasInsecureCors) {
      lines.push(`Instruction (cors): ${INSECURE_CORS_INSTRUCTION}`);
    }
    if (hasCodeError) {
      lines.push(`Instruction (code): ${CODE_ERROR_INSTRUCTION}`);
    }
  }

  return toAsciiSafe(stripAnsiCodes(lines.join('\n')));
}
