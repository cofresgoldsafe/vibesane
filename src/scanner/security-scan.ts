import { toAsciiSafe } from '../text/ascii.js';
import {
  isIgnoredBundledModulePath,
  isPlaceholderSecret,
  isPublicEnvVarName,
  isPublicStripeKey,
} from '../rules/exceptions.js';
import {
  SERVER_ENV_ACCESS_RE,
  isServerEnvVarName,
} from '../rules/server-env.js';
import {
  SECRET_RULES,
  PEM_PRIVATE_KEY_RE,
  EXTRA_TOKENS_RE,
  INLINE_CONN_URI_RE,
  ENV_SECRET_RE,
  PASSWORD_FIELD_RE,
  redactSecret,
  redactPassword,
  redactConnectionUri,
  type SecretMatchContext,
} from '../rules/secrets.js';
import { MASKED_ERROR_RULES } from '../rules/masked-errors.js';

export { redactSecret, redactPassword, redactConnectionUri };

export type SanitySeverity = 'error' | 'warning';
export type SanityIssueKind =
  | 'exposed_file'
  | 'exposed_source_map'
  | 'http_error'
  | 'insecure_cookie'
  | 'insecure_cors'
  | 'insecure_form_method'
  | 'insecure_transport'
  | 'masked_error'
  | 'missing_security_headers'
  | 'secret_leak'
  | 'server_env_in_client'
  | 'slow_route'
  | 'stack_trace_leak'
  | 'syntax_error'
  | 'truncated_body'
  | 'unauthenticated_admin_route'
  | 'unauthenticated_api_route'
  | 'unsanitized_html';

export interface SanityIssue {
  kind: SanityIssueKind;
  severity: SanitySeverity;
  route: string;
  detail: string;
  maskedSnippet?: string;
  codeFrame?: string;
  statusCode?: number;
  elapsedMs?: number;
}

export function stripViteTimestampQuery(pathOrUrl: string): string {
  if (!pathOrUrl) {
    return pathOrUrl;
  }
  return pathOrUrl
    .replace(/\?t=\d+&/g, '?')
    .replace(/\?t=\d+(?=#|$)/g, '')
    .replace(/&t=\d+/g, '');
}

export function detectMaskedError(html: string, route: string): SanityIssue[] {
  if (!html) {
    return [];
  }

  for (const rule of MASKED_ERROR_RULES) {
    if (rule.matches(html)) {
      const viteInfo = extractViteErrorInfo(html, route);
      const nextInfo = !viteInfo ? extractNextErrorInfo(html, route) : null;
      const structured = viteInfo ?? nextInfo;
      const snippet = structured ? structured.summary : rule.label;

      return [
        {
          kind: 'masked_error',
          severity: 'error',
          route,
          detail: `Masked error overlay detected on ${route} (${snippet})`,
          maskedSnippet: snippet,
          ...(viteInfo?.codeFrame ? { codeFrame: viteInfo.codeFrame } : {}),
        },
      ];
    }
  }

  return [];
}

export interface ModuleBoundary {
  readonly index: number;
  readonly path: string;
  readonly isThirdParty: boolean;
}

const WEBPACK_MODULE_DEF_RE =
  /^[\t ]*\/\*\*\*\/ "(?:\([A-Za-z0-9_-]+\)\/)?\.\.?\/([^"\r\n]+)":/gm;

const TURBOPACK_MODULE_DEF_RE =
  /"\[project\]\/([^"\s]+)(?:\s+\[[^\]\r\n]+\])?(?:\s+\((?:ecmascript|hmr-entry)\))?(?:\s+<[^>"\r\n]+>)?"\s*[,:]\s*\(?\(?__turbopack_context__/g;

export function extractModuleBoundaries(content: string): ModuleBoundary[] {
  if (!content) {
    return [];
  }

  const boundaries: ModuleBoundary[] = [];

  WEBPACK_MODULE_DEF_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = WEBPACK_MODULE_DEF_RE.exec(content)) !== null) {
    const rawPath = match[1]?.trim();
    if (!rawPath) {
      continue;
    }
    const cleanPath = rawPath.replace(/^\/+/, '');
    boundaries.push({
      index: match.index,
      path: cleanPath,
      isThirdParty: isIgnoredBundledModulePath(cleanPath),
    });
  }

  TURBOPACK_MODULE_DEF_RE.lastIndex = 0;
  while ((match = TURBOPACK_MODULE_DEF_RE.exec(content)) !== null) {
    const rawPath = match[1]?.trim();
    if (!rawPath) {
      continue;
    }
    const cleanPath = rawPath.replace(/^\/+/, '');
    boundaries.push({
      index: match.index,
      path: cleanPath,
      isThirdParty: isIgnoredBundledModulePath(cleanPath),
    });
  }

  boundaries.sort((a, b) => a.index - b.index);
  return boundaries;
}

export function findModuleBoundaryIndex(
  boundaries: readonly ModuleBoundary[],
  matchIndex: number,
): number {
  if (boundaries.length === 0 || matchIndex < 0) {
    return -1;
  }

  let low = 0;
  let high = boundaries.length - 1;
  let best = -1;

  while (low <= high) {
    const mid = (low + high) >> 1;
    const item = boundaries[mid]!;
    if (item.index <= matchIndex) {
      best = mid;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  return best;
}

export function findModuleBoundary(
  boundaries: readonly ModuleBoundary[],
  matchIndex: number,
): ModuleBoundary | null {
  const idx = findModuleBoundaryIndex(boundaries, matchIndex);
  return idx >= 0 ? boundaries[idx]! : null;
}

export function resolveBundledSourceFile(content: string, matchIndex: number): string | null {
  if (!content || matchIndex <= 0) {
    return null;
  }

  const boundaries = extractModuleBoundaries(content);
  const boundary = findModuleBoundary(boundaries, matchIndex);
  if (!boundary || boundary.isThirdParty) {
    return null;
  }

  return boundary.path;
}

export function scanSecrets(content: string, route: string): SanityIssue[] {
  if (!content) {
    return [];
  }

  const issues: SanityIssue[] = [];
  const seen = new Set<string>();
  const boundaries = extractModuleBoundaries(content);

  const pushIssue = (
    label: string,
    rawSecret: string,
    targetRoute: string,
    customMasked?: string,
  ): void => {
    if (isPublicStripeKey(rawSecret)) {
      return;
    }
    const masked = customMasked ?? redactSecret(rawSecret);
    const dedupeKey = `${targetRoute}::${label}::${masked}`;
    if (seen.has(dedupeKey)) {
      return;
    }
    seen.add(dedupeKey);
    issues.push({
      kind: 'secret_leak',
      severity: 'error',
      route: targetRoute,
      detail: `Secret leak on ${targetRoute}: ${label} (${masked})`,
      maskedSnippet: masked,
    });
  };

  for (const rule of SECRET_RULES) {
    rule.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = rule.regex.exec(content)) !== null) {
      const extracted = rule.extract
        ? rule.extract(match)
        : { value: match[1] ?? '' };
      const rawSecret = extracted.value;
      const ctx: SecretMatchContext = {
        match,
        content,
        matchIndex: match.index,
        ...(extracted.key !== undefined ? { key: extracted.key } : {}),
      };
      if (!rule.accept(rawSecret, ctx)) {
        continue;
      }

      const boundary = findModuleBoundary(boundaries, match.index);
      if (boundary?.isThirdParty) {
        if (rule.kind === 'assignment') {
          continue;
        }
      }

      const targetRoute =
        boundary && !boundary.isThirdParty ? boundary.path : route;

      const resolvedLabel =
        typeof rule.label === 'function' ? rule.label(match) : rule.label;
      const customMasked = rule.mask ? rule.mask(rawSecret) : undefined;
      pushIssue(resolvedLabel, rawSecret, targetRoute, customMasked);
    }
  }

  return issues;
}

export function scanServerEnv(content: string, route: string): SanityIssue[] {
  if (!content) {
    return [];
  }

  const issues: SanityIssue[] = [];
  const seen = new Set<string>();
  const boundaries = extractModuleBoundaries(content);

  SERVER_ENV_ACCESS_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SERVER_ENV_ACCESS_RE.exec(content)) !== null) {
    const varName = match[1] || match[2] || '';
    if (!isServerEnvVarName(varName)) {
      continue;
    }

    const boundary = findModuleBoundary(boundaries, match.index);
    if (boundary?.isThirdParty) {
      continue;
    }

    const targetRoute =
      boundary && !boundary.isThirdParty ? boundary.path : route;
    const dedupeKey = `${targetRoute}::${varName}`;
    if (seen.has(dedupeKey)) {
      continue;
    }
    seen.add(dedupeKey);

    issues.push({
      kind: 'server_env_in_client',
      severity: 'error',
      route: targetRoute,
      detail: `Server environment variable ${varName} referenced in client code on ${targetRoute}`,
      maskedSnippet: varName,
    });
  }

  return issues;
}

export function sanitizeSecretsInText(raw: string): string {
  if (!raw) {
    return '';
  }

  let sanitized = raw.replace(PEM_PRIVATE_KEY_RE, '[REDACTED PRIVATE KEY]');
  for (const rule of SECRET_RULES) {
    if (rule.kind === 'token') {
      sanitized = sanitized.replace(rule.regex, (m) =>
        rule.mask ? rule.mask(m) : redactSecret(m),
      );
    }
  }
  sanitized = sanitized.replace(EXTRA_TOKENS_RE, (m) => redactSecret(m));
  sanitized = sanitized.replace(INLINE_CONN_URI_RE, (m) => redactConnectionUri(m));
  sanitized = sanitized.replace(
    ENV_SECRET_RE,
    (full, varName: string, secretValue: string) => {
      if (
        isPublicEnvVarName(varName) ||
        isPlaceholderSecret(secretValue) ||
        isPublicStripeKey(secretValue)
      ) {
        return full;
      }
      return full.replace(secretValue, redactSecret(secretValue));
    },
  );
  sanitized = sanitized.replace(
    PASSWORD_FIELD_RE,
    (full, qField: string | undefined, bField: string | undefined, passwordValue: string) => {
      void qField;
      void bField;
      if (
        !passwordValue ||
        /\s/.test(passwordValue) ||
        isPlaceholderSecret(passwordValue) ||
        isPublicStripeKey(passwordValue)
      ) {
        return full;
      }
      return full.replace(passwordValue, redactPassword(passwordValue));
    },
  );

  return sanitized;
}

export function sanitizeErrorSnippet(raw: string, maxLen = 140): string {
  if (!raw) {
    return '';
  }

  let sanitized = sanitizeSecretsInText(raw);
  sanitized = sanitized.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  sanitized = sanitizeSecretsInText(sanitized);

  if (sanitized.length > maxLen) {
    return `${sanitized.slice(0, maxLen)}...`;
  }

  return sanitized;
}

const ANSI_ESCAPE_RE = /\x1b\[[0-9;]*m/g;
const APP_DIR_SEGMENTS = ['/src/', '/app/', '/pages/', '/components/'] as const;
const OS_ABSOLUTE_PREFIX_RE =
  /^(?:[A-Za-z]:\/|\/(?:Users|home|var|tmp|opt|private|mnt|root|etc|Volumes)\/)/i;

function extractSafeAppPath(rawPath?: string): string | null {
  if (!rawPath) {
    return null;
  }
  const normalized = stripViteTimestampQuery(rawPath.trim().replace(/\\/g, '/'));
  if (!normalized) {
    return null;
  }

  const withLeadingSlash = normalized.startsWith('/') ? normalized : `/${normalized}`;
  for (const seg of APP_DIR_SEGMENTS) {
    const idx = withLeadingSlash.lastIndexOf(seg);
    if (idx !== -1) {
      return withLeadingSlash.slice(idx);
    }
  }

  if (!OS_ABSOLUTE_PREFIX_RE.test(normalized) && !/^[A-Za-z]:/.test(normalized)) {
    if (normalized.startsWith('/') && normalized !== '/') {
      return normalized;
    }
  }

  return null;
}

export function scrubAbsolutePathsInText(text: string): string {
  if (!text) {
    return '';
  }
  return text.replace(
    /(?:(?<![A-Za-z0-9+.-])[A-Za-z]:[\\/]|\/(?:Users|home|var|tmp|opt|private|mnt|root|etc|Volumes)[\\/])[^\s:"'`<>()]+/gi,
    (match) => {
      const safe = extractSafeAppPath(match);
      if (safe) {
        return safe;
      }
      const norm = stripViteTimestampQuery(match.replace(/\\/g, '/'));
      const parts = norm.split('/').filter(Boolean);
      return parts.length > 0 ? `/${parts[parts.length - 1]}` : norm;
    },
  );
}

function extractBalancedJsonObject(source: string, startBraceIndex: number): string | null {
  if (startBraceIndex < 0 || startBraceIndex >= source.length || source[startBraceIndex] !== '{') {
    return null;
  }
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = startBraceIndex; i < source.length; i += 1) {
    const ch = source[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
    } else if (ch === '{') {
      depth += 1;
    } else if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        return source.slice(startBraceIndex, i + 1);
      }
    }
  }

  return null;
}

function formatCodeFrame(rawFrame?: string): string | undefined {
  if (!rawFrame || typeof rawFrame !== 'string') {
    return undefined;
  }
  const cleaned = toAsciiSafe(
    scrubAbsolutePathsInText(
      sanitizeSecretsInText(toAsciiSafe(rawFrame.replace(ANSI_ESCAPE_RE, ''))),
    ),
  );
  const lines = cleaned.split('\n');
  while (lines.length > 0 && lines[0]!.trim() === '') {
    lines.shift();
  }
  while (lines.length > 0 && lines[lines.length - 1]!.trim() === '') {
    lines.pop();
  }
  if (lines.length === 0) {
    return undefined;
  }
  return lines.slice(0, 10).join('\n');
}

interface ViteErrorPayload {
  message?: unknown;
  frame?: unknown;
  id?: unknown;
  plugin?: unknown;
  loc?: {
    file?: unknown;
    line?: unknown;
    column?: unknown;
  };
}

function parseViteErrorObject(raw: string): ViteErrorPayload | null {
  const assignMatch = /\b(?:const|let|var)\s+error\s*=\s*\{/.exec(raw);
  if (assignMatch) {
    const braceIdx = raw.indexOf('{', assignMatch.index);
    const jsonLiteral = extractBalancedJsonObject(raw, braceIdx);
    if (jsonLiteral) {
      try {
        const parsed = JSON.parse(jsonLiteral) as unknown;
        if (parsed && typeof parsed === 'object') {
          return parsed as ViteErrorPayload;
        }
      } catch {
        // fall through
      }
    }
  }

  const trimmed = raw.trim();
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      if (parsed && typeof parsed === 'object') {
        if (parsed.error && typeof parsed.error === 'object') {
          return parsed.error as ViteErrorPayload;
        }
        if (
          typeof parsed.message === 'string' &&
          ('frame' in parsed || 'loc' in parsed || 'plugin' in parsed || 'id' in parsed)
        ) {
          return parsed as ViteErrorPayload;
        }
      }
    } catch {
      // not valid JSON
    }
  }

  return null;
}

const OXC_FRAME_HEADER_LC_RE = /^\s*(?:╭─|\+-)\[\s*[^\]]+?:(\d+):(\d+)\s*\]\s*$/;
const OXC_TRANSFORM_HEADER_RE = /^(?:x\s+)?Transform failed with \d+ errors?:$/i;
const OXC_CAUSE_LINE_RE = /^\[[A-Z][A-Z0-9_]*\]\s+\S/;

export function extractViteErrorInfo(
  raw: string,
  servedRoute?: string,
): { summary: string; codeFrame?: string } | null {
  if (!raw) {
    return null;
  }

  const cleanServedRoute =
    servedRoute && servedRoute.startsWith('/') && servedRoute !== '/'
      ? stripViteTimestampQuery(servedRoute)
      : null;

  const payload = parseViteErrorObject(raw);
  if (payload && typeof payload.message === 'string' && payload.message.trim().length > 0) {
    const locFile = typeof payload.loc?.file === 'string' ? payload.loc.file : undefined;
    const idFile = typeof payload.id === 'string' ? payload.id : undefined;
    const safeFile =
      (cleanServedRoute && /\.[A-Za-z0-9]+$/.test(cleanServedRoute) ? cleanServedRoute : null) ??
      extractSafeAppPath(locFile) ??
      extractSafeAppPath(idFile) ??
      cleanServedRoute;

    const rawMsgLines = toAsciiSafe(
      payload.message.replace(ANSI_ESCAPE_RE, '').replace(/\r\n/g, '\n'),
    ).split('\n');
    const firstNonEmptyIdx = rawMsgLines.findIndex((line) => line.trim().length > 0);
    const firstLine = firstNonEmptyIdx !== -1 ? rawMsgLines[firstNonEmptyIdx]! : '';

    let summaryLineIdx = firstNonEmptyIdx;
    if (firstNonEmptyIdx !== -1 && OXC_TRANSFORM_HEADER_RE.test(firstLine.trim())) {
      for (let i = firstNonEmptyIdx + 1; i < rawMsgLines.length; i++) {
        if (OXC_CAUSE_LINE_RE.test(rawMsgLines[i]!.trim())) {
          summaryLineIdx = i;
          break;
        }
      }
    }

    let line = typeof payload.loc?.line === 'number' ? payload.loc.line : undefined;
    let column = typeof payload.loc?.column === 'number' ? payload.loc.column : undefined;
    if (line === undefined && summaryLineIdx !== -1) {
      for (const afterLine of rawMsgLines.slice(summaryLineIdx + 1)) {
        const match = OXC_FRAME_HEADER_LC_RE.exec(afterLine);
        if (match) {
          line = Number(match[1]);
          column = Number(match[2]);
          break;
        }
      }
    }

    const lineColSuffix =
      line !== undefined ? `:${line}${column !== undefined ? `:${column}` : ''}` : '';
    const safeLocation = safeFile ? `${safeFile}${lineColSuffix}` : '';

    const summaryRawLine = summaryLineIdx !== -1 ? rawMsgLines[summaryLineIdx]! : '';
    let cleanMessage = toAsciiSafe(
      scrubAbsolutePathsInText(sanitizeSecretsInText(summaryRawLine)),
    )
      .replace(/\s+/g, ' ')
      .trim();

    if (/^x\s+/.test(cleanMessage)) {
      cleanMessage = cleanMessage.replace(/^x\s+/, '').trim();
    }

    if (safeFile && cleanMessage.startsWith(`${safeFile}:`)) {
      cleanMessage = cleanMessage.slice(safeFile.length + 1).trim();
    } else if (safeLocation && cleanMessage.startsWith(`${safeLocation}:`)) {
      cleanMessage = cleanMessage.slice(safeLocation.length + 1).trim();
    }

    const summary =
      safeLocation && !cleanMessage.startsWith(safeLocation)
        ? `${safeLocation} - ${cleanMessage}`
        : cleanMessage;

    let codeFrame: string | undefined;
    if (typeof payload.frame === 'string' && payload.frame.trim().length > 0) {
      codeFrame = formatCodeFrame(payload.frame);
    } else if (summaryLineIdx !== -1 && summaryLineIdx + 1 < rawMsgLines.length) {
      codeFrame = formatCodeFrame(rawMsgLines.slice(summaryLineIdx + 1).join('\n'));
    }

    return {
      summary,
      ...(codeFrame ? { codeFrame } : {}),
    };
  }

  if (
    raw.includes('Transform failed with') ||
    raw.includes('[plugin:vite:') ||
    raw.includes('Pre-transform error:')
  ) {
    const withoutAnsi = toAsciiSafe(raw.replace(ANSI_ESCAPE_RE, '').replace(/\r\n/g, '\n'));
    const strippedTags = withoutAnsi.replace(/<[^>]*>/g, '\n');
    const rawLines = strippedTags.split('\n');

    const firstMsgIdx = rawLines.findIndex((line) => {
      const t = line.trim();
      return (
        t.includes('Transform failed with') ||
        t.includes('[plugin:vite:') ||
        t.includes('Pre-transform error:')
      );
    });

    let promotedCauseIdx = -1;
    if (firstMsgIdx !== -1 && OXC_TRANSFORM_HEADER_RE.test(rawLines[firstMsgIdx]!.trim())) {
      for (let i = firstMsgIdx + 1; i < rawLines.length; i++) {
        if (OXC_CAUSE_LINE_RE.test(rawLines[i]!.trim())) {
          promotedCauseIdx = i;
          break;
        }
      }
    }

    const summaryLineIdx = promotedCauseIdx !== -1 ? promotedCauseIdx : firstMsgIdx;

    const frameLines: string[] = [];
    const messageLines: string[] = [];

    if (promotedCauseIdx !== -1) {
      messageLines.push(rawLines[promotedCauseIdx]!.trim());
    }

    for (let i = 0; i < rawLines.length; i++) {
      const line = rawLines[i]!;
      const trimmedLine = line.trim();
      if (!trimmedLine) {
        continue;
      }
      if (
        /^(?:>\s*)?\d+\s*\|/.test(trimmedLine) ||
        /^\|\s*\^/.test(trimmedLine) ||
        /^\s*[+|]-/.test(line) ||
        /^\s*\|/.test(line) ||
        /^\s*-+\+\s*$/.test(line)
      ) {
        if (promotedCauseIdx === -1 || i > promotedCauseIdx) {
          frameLines.push(line);
        }
      } else if (promotedCauseIdx !== -1) {
        if (i > promotedCauseIdx && OXC_CAUSE_LINE_RE.test(trimmedLine)) {
          frameLines.push(line);
        }
      } else if (
        trimmedLine.includes('Transform failed with') ||
        trimmedLine.includes('[plugin:vite:') ||
        trimmedLine.includes('Pre-transform error:')
      ) {
        messageLines.push(trimmedLine);
      }
    }

    const baseMsg = messageLines.length > 0 ? messageLines.join(' ') : strippedTags;
    let cleanMessage = toAsciiSafe(scrubAbsolutePathsInText(sanitizeSecretsInText(baseMsg)))
      .replace(/\s+/g, ' ')
      .trim();

    if (/^x\s+/.test(cleanMessage)) {
      cleanMessage = cleanMessage.replace(/^x\s+/, '').trim();
    }

    if (!cleanMessage) {
      return null;
    }

    let lineColSuffix = '';
    if (summaryLineIdx !== -1) {
      for (const afterLine of rawLines.slice(summaryLineIdx + 1)) {
        const match = OXC_FRAME_HEADER_LC_RE.exec(afterLine);
        if (match) {
          lineColSuffix = `:${Number(match[1])}:${Number(match[2])}`;
          break;
        }
      }
    }

    const safeFile = cleanServedRoute ?? extractSafeAppPath(cleanMessage);
    const safeLocation = safeFile ? `${safeFile}${lineColSuffix}` : '';
    const summary =
      safeLocation &&
      !cleanMessage.includes(safeLocation) &&
      !cleanMessage.startsWith(safeFile ?? '')
        ? `${safeLocation} - ${cleanMessage}`
        : cleanMessage;
    const codeFrame = frameLines.length > 0 ? formatCodeFrame(frameLines.join('\n')) : undefined;

    return {
      summary,
      ...(codeFrame ? { codeFrame } : {}),
    };
  }

  return null;
}

function cleanNextPagePath(rawPagePath?: string, servedRoute?: string): string | null {
  if (rawPagePath) {
    const normalized = stripViteTimestampQuery(rawPagePath.trim().replace(/\\/g, '/'));
    if (normalized) {
      const withLeadingSlash = normalized.startsWith('/') ? normalized : `/${normalized}`;
      for (const seg of APP_DIR_SEGMENTS) {
        const idx = withLeadingSlash.lastIndexOf(seg);
        if (idx !== -1) {
          return withLeadingSlash.slice(idx + 1);
        }
      }
      if (!OS_ABSOLUTE_PREFIX_RE.test(normalized) && !/^[A-Za-z]:/.test(normalized)) {
        return normalized;
      }
      const parts = normalized.split('/').filter(Boolean);
      if (parts.length >= 2) {
        return parts.slice(-2).join('/');
      }
    }
  }

  if (servedRoute && servedRoute.startsWith('/') && servedRoute !== '/') {
    return stripViteTimestampQuery(servedRoute);
  }

  return null;
}

const ERROR_NAME_RE = /(?:^Error$|Error$|Exception$|^Hydration)/i;
const TYPE_PAGE_THEN_PATH_RE =
  /"type"\s*:\s*"page"[^}{]{0,120}?"pagePath"\s*:\s*"([^"\r\n]+)"/g;
const PATH_THEN_TYPE_PAGE_RE =
  /"pagePath"\s*:\s*"([^"\r\n]+)"[^}{]{0,120}?"type"\s*:\s*"page"/g;
const ANY_PAGE_PATH_RE = /"pagePath"\s*:\s*"([^"\r\n]+)"/g;

function selectNextPagePath(normalized: string): string | undefined {
  let match: RegExpExecArray | null;
  let typedPageCandidate: string | undefined;

  TYPE_PAGE_THEN_PATH_RE.lastIndex = 0;
  while ((match = TYPE_PAGE_THEN_PATH_RE.exec(normalized)) !== null) {
    const candidate = match[1]?.trim();
    if (candidate && !candidate.includes('__next_builtin__')) {
      typedPageCandidate = candidate;
    }
  }

  PATH_THEN_TYPE_PAGE_RE.lastIndex = 0;
  while ((match = PATH_THEN_TYPE_PAGE_RE.exec(normalized)) !== null) {
    const candidate = match[1]?.trim();
    if (candidate && !candidate.includes('__next_builtin__')) {
      typedPageCandidate = candidate;
    }
  }

  if (typedPageCandidate) {
    return typedPageCandidate;
  }

  const validPaths: string[] = [];
  ANY_PAGE_PATH_RE.lastIndex = 0;
  while ((match = ANY_PAGE_PATH_RE.exec(normalized)) !== null) {
    const candidate = match[1]?.trim();
    if (candidate && !candidate.includes('__next_builtin__')) {
      validPaths.push(candidate);
    }
  }

  if (validPaths.length === 0) {
    return undefined;
  }

  for (let i = validPaths.length - 1; i >= 0; i -= 1) {
    const p = validPaths[i]!;
    if (/(?:^|[\\/])page\.[A-Za-z0-9]+$/i.test(p)) {
      return p;
    }
  }

  return validPaths[validPaths.length - 1];
}

export function extractNextErrorInfo(
  raw: string,
  servedRoute?: string,
): { summary: string; codeFrame?: string } | null {
  if (!raw) {
    return null;
  }

  const normalized = raw
    .replace(/\\\\"/g, "'")
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, '/');

  const rawPagePath = selectNextPagePath(normalized);

  const pairRegexes = [
    /"name"\s*:\s*"([^"\r\n]+)"\s*,\s*"message"\s*:\s*"([^"\r\n]+)"/g,
    /"message"\s*:\s*"([^"\r\n]+)"\s*,\s*"name"\s*:\s*"([^"\r\n]+)"/g,
  ] as const;

  for (let rIdx = 0; rIdx < pairRegexes.length; rIdx += 1) {
    const regex = pairRegexes[rIdx]!;
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(normalized)) !== null) {
      const errName = (rIdx === 0 ? match[1] : match[2])?.trim();
      const errMsg = (rIdx === 0 ? match[2] : match[1])?.trim();
      if (!errName || !errMsg) {
        continue;
      }

      const windowStart = Math.max(0, match.index - 300);
      const windowEnd = Math.min(normalized.length, match.index + match[0].length + 300);
      const contextWindow = normalized.slice(windowStart, windowEnd);
      const hasErrorContext =
        ERROR_NAME_RE.test(errName) ||
        contextWindow.includes('"pagePath"') ||
        contextWindow.includes('"digest"') ||
        contextWindow.includes('"__next');

      if (!hasErrorContext) {
        continue;
      }

      const cleanMsg = toAsciiSafe(
        scrubAbsolutePathsInText(sanitizeSecretsInText(errMsg))
          .replace(/\s+/g, ' ')
          .trim(),
      );
      const targetPath = cleanNextPagePath(rawPagePath, servedRoute);
      const summary = targetPath
        ? `${targetPath} - ${errName}: ${cleanMsg}`
        : `${errName}: ${cleanMsg}`;

      return { summary };
    }
  }

  return null;
}
