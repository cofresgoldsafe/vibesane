export type SanitySeverity = 'error' | 'warning';
export type SanityIssueKind = 'http_error' | 'masked_error' | 'secret_leak' | 'slow_route';

export interface SanityIssue {
  kind: SanityIssueKind;
  severity: SanitySeverity;
  route: string;
  detail: string;
  maskedSnippet?: string;
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
      return [
        {
          kind: 'masked_error',
          severity: 'error',
          route,
          detail: `Masked error overlay detected on ${route} (${rule.label})`,
          maskedSnippet: rule.label,
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
  /\b([A-Z][A-Z0-9_]*(?:_SECRET|_PRIVATE_KEY))["'`]?\s*[:=]\s*["'`]([^"'`\r\n]{6,})["'`]/g;
const DATABASE_URL_RE =
  /\b(DATABASE_URL)["'`]?\s*[:=]\s*["'`]((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s"'`]+:[^@\s"'`]+@[^"'`\s]+)["'`]/g;
const PASSWORD_FIELD_RE =
  /(?:["'](password|passwd|pwd|senha)["']|\b(password|passwd|pwd|senha))\s*:\s*["']([^"'\r\n]{4,})["']/gi;

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
  if (/^[*•xX._-]+$/.test(trimmed)) {
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

export function scanSecrets(content: string, route: string): SanityIssue[] {
  if (!content) {
    return [];
  }

  const issues: SanityIssue[] = [];
  const seen = new Set<string>();

  const pushIssue = (label: string, rawSecret: string): void => {
    if (isPublicStripeKey(rawSecret)) {
      return;
    }
    const masked = redactSecret(rawSecret);
    const dedupeKey = `${route}::${label}::${masked}`;
    if (seen.has(dedupeKey)) {
      return;
    }
    seen.add(dedupeKey);
    issues.push({
      kind: 'secret_leak',
      severity: 'error',
      route,
      detail: `Secret leak on ${route}: ${label} (${masked})`,
      maskedSnippet: masked,
    });
  };

  let match: RegExpExecArray | null;

  STRIPE_SECRET_RE.lastIndex = 0;
  while ((match = STRIPE_SECRET_RE.exec(content)) !== null) {
    const token = match[1];
    if (token) {
      pushIssue('Stripe secret key', token);
    }
  }

  GOOGLE_API_KEY_RE.lastIndex = 0;
  while ((match = GOOGLE_API_KEY_RE.exec(content)) !== null) {
    const token = match[1];
    if (token) {
      pushIssue('Google API key', token);
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
    pushIssue(label, token);
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
    pushIssue(varName, secretValue);
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
    pushIssue(varName, connString);
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
    pushIssue(`Hardcoded ${fieldName.toLowerCase()}`, passwordValue);
  }

  return issues;
}

const PEM_PRIVATE_KEY_RE =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g;
const INLINE_CONN_URI_RE =
  /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s"'`]+:[^@\s"'`]+@[^"'`\s]+)/g;
const EXTRA_TOKENS_RE =
  /\b(AKIA[0-9A-Z]{16}|glpat-[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,})\b/g;

export function sanitizeErrorSnippet(raw: string, maxLen = 140): string {
  if (!raw) {
    return '';
  }

  let sanitized = raw.replace(PEM_PRIVATE_KEY_RE, '[REDACTED PRIVATE KEY]');
  sanitized = sanitized.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();

  sanitized = sanitized.replace(STRIPE_SECRET_RE, (m) => redactSecret(m));
  sanitized = sanitized.replace(GOOGLE_API_KEY_RE, (m) => redactSecret(m));
  sanitized = sanitized.replace(PROVIDER_TOKEN_RE, (m) => redactSecret(m));
  sanitized = sanitized.replace(EXTRA_TOKENS_RE, (m) => redactSecret(m));
  sanitized = sanitized.replace(INLINE_CONN_URI_RE, (m) => redactSecret(m));
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
      return full.replace(passwordValue, redactSecret(passwordValue));
    },
  );

  if (sanitized.length > maxLen) {
    return `${sanitized.slice(0, maxLen)}...`;
  }

  return sanitized;
}
