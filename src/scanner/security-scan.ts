import { toAsciiSafe } from '../text/ascii.js';

export type SanitySeverity = 'error' | 'warning';
export type SanityIssueKind = 'http_error' | 'masked_error' | 'secret_leak' | 'slow_route';

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

const KNOWN_SECRET_PREFIXES = [
  'sk_live_',
  'sk_test_',
  'rk_live_',
  'rk_test_',
  'AIzaSy',
  'ghp_',
  'sk-proj-',
  'sk-ant-',
] as const;

export function redactSecret(secret: string): string {
  for (const prefix of KNOWN_SECRET_PREFIXES) {
    if (secret.startsWith(prefix)) {
      if (secret.length <= prefix.length + 4) {
        return `${prefix}****`;
      }
      return `${prefix}****${secret.slice(-4)}`;
    }
  }

  if (secret.length <= 8) {
    return '****';
  }

  return `${secret.slice(0, 3)}****${secret.slice(-2)}`;
}

export function redactPassword(raw: string): string {
  if (!raw || raw.length === 0) {
    return '***';
  }
  return `${raw[0]}***`;
}

const CONN_URI_PARTS_RE =
  /^((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s"'`@]+:)([^@\s"'`]+)(@[^\s"'`]+)$/i;

export function redactConnectionUri(uri: string): string {
  if (!uri) {
    return '****';
  }
  const trimmed = uri.trim();
  const match = CONN_URI_PARTS_RE.exec(trimmed);
  if (match) {
    return `${match[1]}****${match[3]}`;
  }
  const replaced = trimmed.replace(
    /((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s"'`@]+:)([^@\s"'`]+)(@)/gi,
    '$1****$3',
  );
  if (replaced !== trimmed) {
    return replaced;
  }
  return redactSecret(trimmed);
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

interface MaskedErrorRule {
  label: string;
  matches: (html: string) => boolean;
}

const NEXT_DATA_SCRIPT_RE = /<script\b[^>]*\bid=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/gi;
const TITLE_500_RE = /<title\b[^>]*>\s*(?:500(?:\b|\s|:|-)|Internal Server Error\b)/i;
const H1_500_RE = /<h1\b[^>]*>\s*(?:500(?:\b|\s|:|-)|Internal Server Error\b)/i;

function hasNextDataError(html: string): boolean {
  NEXT_DATA_SCRIPT_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  let foundClosedTag = false;
  while ((match = NEXT_DATA_SCRIPT_RE.exec(html)) !== null) {
    foundClosedTag = true;
    const body = match[1] ?? '';
    if (
      /"err"\s*:\s*\{\s*"name"\s*:/.test(body) ||
      /"statusCode"\s*:\s*500\b/.test(body)
    ) {
      return true;
    }
  }

  if (foundClosedTag) {
    return false;
  }

  const nextDataIdx = html.indexOf('<script id="__NEXT_DATA__"');
  if (nextDataIdx !== -1) {
    const truncatedTail = html.slice(nextDataIdx);
    if (
      /"err"\s*:\s*\{\s*"name"\s*:/.test(truncatedTail) ||
      /"statusCode"\s*:\s*500\b/.test(truncatedTail)
    ) {
      return true;
    }
  }

  return false;
}

function hasNextErrorContext(html: string): boolean {
  if (/id=["']__next_error__["']/.test(html)) {
    return true;
  }
  if (
    html.includes('__next_error__') &&
    (html.includes('Server Error') || html.includes('Unhandled Runtime Error'))
  ) {
    return true;
  }
  return false;
}

const MASKED_ERROR_RULES: readonly MaskedErrorRule[] = [
  {
    label: 'nextjs__container_errors',
    matches: (html) => html.includes('nextjs__container_errors'),
  },
  {
    label: 'Unhandled Runtime Error',
    matches: (html) => html.includes('Unhandled Runtime Error'),
  },
  {
    label: 'Application error: a client-side exception has occurred',
    matches: (html) => html.includes('Application error: a client-side exception has occurred'),
  },
  {
    label: '__next_error__',
    matches: (html) => hasNextErrorContext(html),
  },
  {
    label: '<nextjs-portal',
    matches: (html) => html.includes('<nextjs-portal'),
  },
  {
    label: '__NEXT_DATA__ error payload',
    matches: (html) => hasNextDataError(html),
  },
  {
    label: 'vite-error-overlay',
    matches: (html) => html.includes('<vite-error-overlay') || html.includes('vite-error-overlay'),
  },
  {
    label: '[plugin:vite:',
    matches: (html) => html.includes('[plugin:vite:'),
  },
  {
    label: 'Pre-transform error:',
    matches: (html) => html.includes('Pre-transform error:'),
  },
  {
    label: 'HTML 500 / Internal Server Error heading',
    matches: (html) => TITLE_500_RE.test(html) || H1_500_RE.test(html),
  },
];

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

const STRIPE_SECRET_RE = /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{10,})\b/g;
const GOOGLE_API_KEY_RE = /\b(AIzaSy[0-9A-Za-z_-]{33})\b/g;
const PROVIDER_TOKEN_RE =
  /\b(ghp_[0-9A-Za-z]{20,}|sk-proj-[0-9A-Za-z_-]{16,}|sk-ant-[0-9A-Za-z_-]{16,})\b/g;
const ENV_SECRET_RE =
  /\b([A-Z][A-Z0-9_]*(?:_SECRET|_PRIVATE_KEY))(?:\\?["'`])?\s*[:=]\s*\\?["'`]([^"'`\\\r\n]{6,})\\?["'`]/g;
const DATABASE_URL_RE =
  /\b(DATABASE_URL)(?:\\?["'`])?\s*[:=]\s*\\?["'`]((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s"'`\\]+:[^@\s"'`\\]+@[^"'`\\\s]+)\\?["'`]/g;
const PASSWORD_FIELD_RE =
  /(?:\\?["'](password|passwd|pwd|senha)\\?["']|\b(password|passwd|pwd|senha))\s*:\s*\\?["']([^"'\\\r\n]{4,})\\?["']/gi;

const PLACEHOLDER_VALUES = new Set([
  '***',
  '****',
  '<secret>',
  '<password>',
  'your-secret',
  'your_secret',
  'your-password',
  'your_password',
  'changeme',
  'password',
  'passwd',
  'pwd',
  'senha',
  'example',
  'placeholder',
  '••••••••',
  'process.env',
]);

function isPlaceholderSecret(value: string): boolean {
  const trimmed = value.trim();
  const normalized = trimmed.toLowerCase();
  if (!trimmed) {
    return true;
  }
  if (PLACEHOLDER_VALUES.has(normalized)) {
    return true;
  }
  if (/^[*•xX._-]+$/.test(trimmed) || /^[^*]\*{3}$/.test(trimmed)) {
    return true;
  }
  if (/^<[^>]+>$/.test(trimmed) || /^\$\{[^}]+\}$/.test(trimmed)) {
    return true;
  }
  if (normalized.startsWith('process.env.') || normalized.startsWith('import.meta.env.')) {
    return true;
  }
  if (normalized.includes('your-') || normalized.includes('your_') || normalized.includes('changeme')) {
    return true;
  }
  return false;
}

function startsWithKnownTokenPrefix(value: string): boolean {
  return KNOWN_SECRET_PREFIXES.some((prefix) => value.startsWith(prefix));
}

function isPublicStripeKey(value: string): boolean {
  return value.startsWith('pk_live_') || value.startsWith('pk_test_');
}

function isHtmlAttributeContext(content: string, matchIndex: number): boolean {
  const lookbehindStart = Math.max(0, matchIndex - 120);
  const before = content.slice(lookbehindStart, matchIndex);
  const lastOpenTag = before.lastIndexOf('<');
  const lastCloseTag = before.lastIndexOf('>');
  if (lastOpenTag !== -1 && lastOpenTag > lastCloseTag) {
    return true;
  }
  if (/(?:type|name|id|for|placeholder|autocomplete)\s*=\s*["']?$/i.test(before)) {
    return true;
  }
  return false;
}

const TURBOPACK_MODULE_MARKER_RE =
  /\[project\]\/([A-Za-z0-9_./[\]-]+\.[A-Za-z0-9]+)(?:\s+\[[^\]]+\])?(?:\s+\((?:ecmascript|hmr-entry)\))?/g;
const WEBPACK_MODULE_MARKER_RE =
  /(?:\([A-Za-z0-9_-]+\)\/)?\.\.?\/((?:src|app|pages|components)\/[A-Za-z0-9_./[\]-]+\.[A-Za-z0-9]+)/g;

function isIgnoredBundledModulePath(candidatePath: string): boolean {
  const lower = candidatePath.toLowerCase();
  return (
    lower.includes('node_modules') ||
    lower.includes('next/dist') ||
    lower.includes('next_dist')
  );
}

export function resolveBundledSourceFile(content: string, matchIndex: number): string | null {
  if (!content || matchIndex <= 0) {
    return null;
  }

  const prefix = content.slice(0, matchIndex);
  let bestIndex = -1;
  let bestPath: string | null = null;

  let match: RegExpExecArray | null;

  TURBOPACK_MODULE_MARKER_RE.lastIndex = 0;
  while ((match = TURBOPACK_MODULE_MARKER_RE.exec(prefix)) !== null) {
    const candidate = match[1]?.trim();
    if (!candidate || isIgnoredBundledModulePath(candidate)) {
      continue;
    }
    if (match.index > bestIndex) {
      bestIndex = match.index;
      bestPath = candidate.replace(/^\/+/, '');
    }
  }

  WEBPACK_MODULE_MARKER_RE.lastIndex = 0;
  while ((match = WEBPACK_MODULE_MARKER_RE.exec(prefix)) !== null) {
    const candidate = match[1]?.trim();
    if (!candidate || isIgnoredBundledModulePath(candidate)) {
      continue;
    }
    if (match.index > bestIndex) {
      bestIndex = match.index;
      bestPath = candidate.replace(/^\/+/, '');
    }
  }

  return bestPath;
}

export function scanSecrets(content: string, route: string): SanityIssue[] {
  if (!content) {
    return [];
  }

  const issues: SanityIssue[] = [];
  const seen = new Set<string>();

  const pushIssue = (
    label: string,
    rawSecret: string,
    customMasked?: string,
    matchIndex?: number,
  ): void => {
    if (isPublicStripeKey(rawSecret)) {
      return;
    }
    const resolvedSource =
      (matchIndex !== undefined ? resolveBundledSourceFile(content, matchIndex) : null) ?? route;
    const masked = customMasked ?? redactSecret(rawSecret);
    const dedupeKey = `${resolvedSource}::${label}::${masked}`;
    if (seen.has(dedupeKey)) {
      return;
    }
    seen.add(dedupeKey);
    issues.push({
      kind: 'secret_leak',
      severity: 'error',
      route: resolvedSource,
      detail: `Secret leak on ${resolvedSource}: ${label} (${masked})`,
      maskedSnippet: masked,
    });
  };

  let match: RegExpExecArray | null;

  STRIPE_SECRET_RE.lastIndex = 0;
  while ((match = STRIPE_SECRET_RE.exec(content)) !== null) {
    const token = match[1];
    if (token) {
      pushIssue('Stripe secret key', token, undefined, match.index);
    }
  }

  GOOGLE_API_KEY_RE.lastIndex = 0;
  while ((match = GOOGLE_API_KEY_RE.exec(content)) !== null) {
    const token = match[1];
    if (token) {
      pushIssue('Google API key', token, undefined, match.index);
    }
  }

  PROVIDER_TOKEN_RE.lastIndex = 0;
  while ((match = PROVIDER_TOKEN_RE.exec(content)) !== null) {
    const token = match[1];
    if (!token) {
      continue;
    }
    const label = token.startsWith('ghp_')
      ? 'GitHub token'
      : token.startsWith('sk-proj-')
        ? 'OpenAI API key'
        : 'Anthropic API key';
    pushIssue(label, token, undefined, match.index);
  }

  ENV_SECRET_RE.lastIndex = 0;
  while ((match = ENV_SECRET_RE.exec(content)) !== null) {
    const varName = match[1];
    const secretValue = match[2];
    if (!varName || !secretValue) {
      continue;
    }
    if (varName.startsWith('NEXT_PUBLIC_') || varName.startsWith('VITE_')) {
      continue;
    }
    if (
      isPlaceholderSecret(secretValue) ||
      isPublicStripeKey(secretValue) ||
      startsWithKnownTokenPrefix(secretValue)
    ) {
      continue;
    }
    pushIssue(varName, secretValue, undefined, match.index);
  }

  DATABASE_URL_RE.lastIndex = 0;
  while ((match = DATABASE_URL_RE.exec(content)) !== null) {
    const varName = match[1];
    const connString = match[2];
    if (!varName || !connString) {
      continue;
    }
    if (isPlaceholderSecret(connString)) {
      continue;
    }
    pushIssue(varName, connString, redactConnectionUri(connString), match.index);
  }

  PASSWORD_FIELD_RE.lastIndex = 0;
  while ((match = PASSWORD_FIELD_RE.exec(content)) !== null) {
    const fieldName = match[1] ?? match[2] ?? 'password';
    const passwordValue = match[3];
    if (!passwordValue || /\s/.test(passwordValue)) {
      continue;
    }
    if (isHtmlAttributeContext(content, match.index)) {
      continue;
    }
    if (
      isPlaceholderSecret(passwordValue) ||
      isPublicStripeKey(passwordValue) ||
      startsWithKnownTokenPrefix(passwordValue)
    ) {
      continue;
    }
    pushIssue(
      `Hardcoded ${fieldName.toLowerCase()}`,
      passwordValue,
      redactPassword(passwordValue),
      match.index,
    );
  }

  return issues;
}

const PEM_PRIVATE_KEY_RE =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g;
const INLINE_CONN_URI_RE =
  /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s"'`\\]+:[^@\s"'`\\]+@[^"'`\\\s]+)/g;
const EXTRA_TOKENS_RE =
  /\b(AKIA[0-9A-Z]{16}|glpat-[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,})\b/g;

export function sanitizeSecretsInText(raw: string): string {
  if (!raw) {
    return '';
  }

  let sanitized = raw.replace(PEM_PRIVATE_KEY_RE, '[REDACTED PRIVATE KEY]');
  sanitized = sanitized.replace(STRIPE_SECRET_RE, (m) => redactSecret(m));
  sanitized = sanitized.replace(GOOGLE_API_KEY_RE, (m) => redactSecret(m));
  sanitized = sanitized.replace(PROVIDER_TOKEN_RE, (m) => redactSecret(m));
  sanitized = sanitized.replace(EXTRA_TOKENS_RE, (m) => redactSecret(m));
  sanitized = sanitized.replace(INLINE_CONN_URI_RE, (m) => redactConnectionUri(m));
  sanitized = sanitized.replace(
    ENV_SECRET_RE,
    (full, varName: string, secretValue: string) => {
      if (
        varName.startsWith('NEXT_PUBLIC_') ||
        varName.startsWith('VITE_') ||
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

function scrubAbsolutePathsInText(text: string): string {
  if (!text) {
    return '';
  }
  return text.replace(
    /(?:[A-Za-z]:[\\/]|\/(?:Users|home|var|tmp|opt|private|mnt|root|etc|Volumes)[\\/])[^\s:"'`<>()]+/gi,
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
    sanitizeSecretsInText(
      scrubAbsolutePathsInText(toAsciiSafe(rawFrame.replace(ANSI_ESCAPE_RE, ''))),
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

    const line = typeof payload.loc?.line === 'number' ? payload.loc.line : undefined;
    const column = typeof payload.loc?.column === 'number' ? payload.loc.column : undefined;
    const lineColSuffix =
      line !== undefined ? `:${line}${column !== undefined ? `:${column}` : ''}` : '';
    const safeLocation = safeFile ? `${safeFile}${lineColSuffix}` : '';

    const rawMsgLines = toAsciiSafe(
      payload.message.replace(ANSI_ESCAPE_RE, '').replace(/\r\n/g, '\n'),
    ).split('\n');
    const firstNonEmptyIdx = rawMsgLines.findIndex((line) => line.trim().length > 0);
    const firstLine = firstNonEmptyIdx !== -1 ? rawMsgLines[firstNonEmptyIdx]! : '';

    let cleanMessage = toAsciiSafe(
      sanitizeSecretsInText(scrubAbsolutePathsInText(firstLine)),
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
    } else if (firstNonEmptyIdx !== -1 && firstNonEmptyIdx + 1 < rawMsgLines.length) {
      codeFrame = formatCodeFrame(rawMsgLines.slice(firstNonEmptyIdx + 1).join('\n'));
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

    const frameLines: string[] = [];
    const messageLines: string[] = [];

    for (const line of rawLines) {
      const trimmedLine = line.trim();
      if (!trimmedLine) {
        continue;
      }
      if (
        /^(?:>\s*)?\d+\s*\|/.test(trimmedLine) ||
        /^\|\s*\^/.test(trimmedLine) ||
        /^\s*[+|]-/.test(line) ||
        /^\s*\|/.test(line)
      ) {
        frameLines.push(line);
      } else if (
        trimmedLine.includes('Transform failed with') ||
        trimmedLine.includes('[plugin:vite:') ||
        trimmedLine.includes('Pre-transform error:')
      ) {
        messageLines.push(trimmedLine);
      }
    }

    const baseMsg = messageLines.length > 0 ? messageLines.join(' ') : strippedTags;
    const cleanMessage = toAsciiSafe(sanitizeSecretsInText(scrubAbsolutePathsInText(baseMsg)))
      .replace(/\s+/g, ' ')
      .trim();

    if (!cleanMessage) {
      return null;
    }

    const safeFile = cleanServedRoute ?? extractSafeAppPath(cleanMessage);
    const summary =
      safeFile && !cleanMessage.includes(safeFile)
        ? `${safeFile} - ${cleanMessage}`
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
        sanitizeSecretsInText(scrubAbsolutePathsInText(errMsg))
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
