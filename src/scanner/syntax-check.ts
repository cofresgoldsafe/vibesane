import vm from 'node:vm';
import { spawn } from 'node:child_process';
import { toAsciiSafe } from '../text/ascii.js';
import {
  sanitizeSecretsInText,
  scrubAbsolutePathsInText,
  type SanityIssue,
} from './security-scan.js';

export interface CheckScriptSyntaxOptions {
  code: string;
  route: string;
  isModule?: boolean;
  contentType?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
  rootHasViteClient?: boolean;
}

const MODULE_ERROR_PATTERNS = [
  'Cannot use import statement outside a module',
  "Unexpected token 'export'",
  "Cannot use 'import.meta' outside a module",
  'await is only valid in async functions and the top level bodies of modules',
] as const;

export function formatSyntaxCodeFrame(
  code: string,
  targetLine: number,
  targetCol: number,
  maxWindow = 160,
): string {
  const lines = code.split(/\r?\n/);
  if (lines.length === 0) {
    return '';
  }
  const lineIdx = Math.max(0, Math.min(lines.length - 1, targetLine - 1));
  const rawTargetLine = lines[lineIdx] ?? '';

  let displayLine = rawTargetLine;
  let pointerCol = Math.max(1, targetCol);

  if (rawTargetLine.length > maxWindow) {
    const col0 = Math.max(0, pointerCol - 1);
    const half = Math.floor(maxWindow / 2);
    let start = Math.max(0, col0 - half);
    let end = Math.min(rawTargetLine.length, start + maxWindow);
    if (end - start < maxWindow && start > 0) {
      start = Math.max(0, end - maxWindow);
    }
    const leftDots = start > 0 ? '...' : '';
    const rightDots = end < rawTargetLine.length ? '...' : '';
    const sliced = rawTargetLine.slice(start, end);
    displayLine = `${leftDots}${sliced}${rightDots}`;
    pointerCol = col0 - start + leftDots.length + 1;
  }

  const frameParts: string[] = [];
  const startLineIdx = Math.max(0, lineIdx - 2);
  const endLineIdx = Math.min(lines.length - 1, lineIdx + 1);

  for (let i = startLineIdx; i <= endLineIdx; i++) {
    const lineNum = String(i + 1).padStart(4, ' ');
    if (i === lineIdx) {
      frameParts.push(`${lineNum} | ${displayLine}`);
      const pointer = ' '.repeat(Math.max(0, pointerCol - 1)) + '^';
      frameParts.push(`     | ${pointer}`);
    } else {
      let ctxLine = lines[i] ?? '';
      if (ctxLine.length > maxWindow) {
        ctxLine = `${ctxLine.slice(0, maxWindow)}...`;
      }
      frameParts.push(`${lineNum} | ${ctxLine}`);
    }
  }

  const rawFrame = frameParts.slice(0, 10).join('\n');
  return toAsciiSafe(scrubAbsolutePathsInText(sanitizeSecretsInText(rawFrame)));
}

function checkEsmSyntaxAsync(
  code: string,
  route: string,
  signal?: AbortSignal,
  timeoutMs = 2000,
): Promise<SanityIssue | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: SanityIssue | null): void => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };

    if (signal?.aborted) {
      return finish(null);
    }

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(process.execPath, ['--check', '--input-type=module'], {
        windowsHide: true,
        signal,
        timeout: Math.max(100, timeoutMs),
      });
    } catch {
      return finish(null);
    }

    let stderr = '';

    child.stderr?.on('data', (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });

    child.on('error', () => {
      finish(null);
    });

    child.on('close', (exitCode) => {
      if (exitCode === 0 || !stderr.trim()) {
        return finish(null);
      }

      const lines = stderr.split(/\r?\n/);
      let lineNum = 1;
      let colNum = 1;
      let syntaxErrorMsg = 'SyntaxError';

      const lineMatch = stderr.match(/\[stdin\]:(\d+)/);
      if (lineMatch?.[1]) {
        lineNum = parseInt(lineMatch[1], 10);
      }

      for (let i = 0; i < Math.min(lines.length, 6); i++) {
        const l = lines[i];
        if (l && l.includes('^')) {
          colNum = l.indexOf('^') + 1;
          break;
        }
      }

      const msgMatch = stderr.match(/(?:SyntaxError|TypeError|Error):\s*([^\r\n]+)/);
      if (msgMatch?.[1]) {
        syntaxErrorMsg = msgMatch[1].trim();
      }

      if (syntaxErrorMsg.includes('Unexpected end of input')) {
        const allLines = code.split(/\r?\n/);
        lineNum = allLines.length;
        const lastLineStr = allLines[allLines.length - 1] ?? '';
        colNum = Math.max(1, lastLineStr.length + 1);
      }

      const frame = formatSyntaxCodeFrame(code, lineNum, colNum);
      const detail = `Syntax error on script ${route}: ${syntaxErrorMsg}`;

      finish({
        kind: 'syntax_error',
        severity: 'error',
        route,
        detail,
        codeFrame: frame,
      });
    });

    try {
      child.stdin?.end(code);
    } catch {
      finish(null);
    }
  });
}

export async function checkScriptSyntax(
  options: CheckScriptSyntaxOptions,
): Promise<SanityIssue | null> {
  const code = options.code;
  if (!code || typeof code !== 'string') {
    return null;
  }

  const rawContentType = (options.contentType ?? '').toLowerCase();
  if (rawContentType.includes('json')) {
    return null;
  }

  const clean = code.charCodeAt(0) === 0xfeff ? code.slice(1) : code;
  const trimmed = clean.trimStart();
  const isHtml =
    trimmed.startsWith('<') || rawContentType.includes('text/html');

  if (isHtml) {
    return {
      kind: 'syntax_error',
      severity: 'error',
      route: options.route,
      detail: `Script ${options.route} returned HTML instead of JavaScript (the file probably does not exist and the server fell back to index.html)`,
    };
  }

  if (code.includes('/@vite/client')) {
    return null;
  }

  if (options.rootHasViteClient && options.isModule) {
    return null;
  }

  const timeoutMs = options.timeoutMs ?? 2000;

  if (options.isModule) {
    return checkEsmSyntaxAsync(code, options.route, options.signal, timeoutMs);
  }

  try {
    new vm.Script(code, { filename: options.route });
    return null;
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    const shouldPromoteToEsm = MODULE_ERROR_PATTERNS.some((pat) =>
      errMsg.includes(pat),
    );

    if (shouldPromoteToEsm) {
      if (options.rootHasViteClient) {
        return null;
      }
      return checkEsmSyntaxAsync(code, options.route, options.signal, timeoutMs);
    }

    const stack =
      err instanceof Error && typeof err.stack === 'string' ? err.stack : '';
    const stackLines = stack.split(/\r?\n/);
    let lineNum = 1;
    let colNum = 1;

    const locMatch = stackLines[0]?.match(/:(\d+)(?::(\d+))?$/);
    if (locMatch?.[1]) {
      lineNum = parseInt(locMatch[1], 10);
      if (locMatch[2]) {
        colNum = parseInt(locMatch[2], 10);
      }
    }

    for (let i = 1; i < Math.min(stackLines.length, 6); i++) {
      const l = stackLines[i];
      if (l && l.includes('^')) {
        colNum = l.indexOf('^') + 1;
        break;
      }
    }

    if (errMsg.includes('Unexpected end of input')) {
      const allLines = code.split(/\r?\n/);
      lineNum = allLines.length;
      const lastLineStr = allLines[allLines.length - 1] ?? '';
      colNum = Math.max(1, lastLineStr.length + 1);
    }

    const frame = formatSyntaxCodeFrame(code, lineNum, colNum);
    return {
      kind: 'syntax_error',
      severity: 'error',
      route: options.route,
      detail: `Syntax error on script ${options.route}: ${errMsg}`,
      codeFrame: frame,
    };
  }
}
