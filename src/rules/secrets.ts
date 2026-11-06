import {
  isHtmlAttributeContext,
  isPlaceholderSecret,
  isPublicEnvVarName,
  isPublicStripeKey,
} from './exceptions.js';

export type SecretRuleKind = 'token' | 'assignment';

export interface SecretMatchContext {
  readonly match: RegExpExecArray;
  readonly content: string;
  readonly matchIndex: number;
  readonly key?: string;
}

export interface SecretRule {
  readonly id: string;
  readonly kind: SecretRuleKind;
  readonly label: string | ((match: RegExpExecArray) => string);
  readonly regex: RegExp;
  readonly tokenPrefixes?: readonly string[];
  readonly extract?: (match: RegExpExecArray) => { key?: string; value: string };
  readonly accept: (value: string, ctx: SecretMatchContext) => boolean;
  readonly mask?: (raw: string) => string;
  readonly examples: {
    readonly shouldDetect: readonly string[];
    readonly shouldIgnore: readonly string[];
  };
}

export const STRIPE_SECRET_RE = /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{10,})\b/g;
export const GOOGLE_API_KEY_RE = /\b(AIzaSy[0-9A-Za-z_-]{33})\b/g;
export const PROVIDER_TOKEN_RE =
  /\b(ghp_[0-9A-Za-z]{20,}|sk-proj-[0-9A-Za-z_-]{16,}|sk-ant-[0-9A-Za-z_-]{16,})\b/g;
export const ENV_SECRET_RE =
  /\b([A-Z][A-Z0-9_]*(?:_SECRET|_PRIVATE_KEY))(?:\\?["'`])?\s*[:=]\s*\\?["'`]([^"'`\\\r\n]{6,})\\?["'`]/g;
export const DATABASE_URL_RE =
  /\b(DATABASE_URL)(?:\\?["'`])?\s*[:=]\s*\\?["'`]((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s"'`\\]+:[^@\s"'`\\]+@[^"'`\\\s]+)\\?["'`]/g;
export const PASSWORD_FIELD_RE =
  /(?:\\?["'](password|passwd|pwd|senha)\\?["']|\b(password|passwd|pwd|senha))\s*:\s*\\?["']([^"'\\\r\n]{4,})\\?["']/gi;

export const PEM_PRIVATE_KEY_RE =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g;
export const INLINE_CONN_URI_RE =
  /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s"'`\\]+:[^@\s"'`\\]+@[^"'`\\\s]+)/g;
export const EXTRA_TOKENS_RE =
  /\b(AKIA[0-9A-Z]{16}|glpat-[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,})\b/g;

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

export function startsWithKnownTokenPrefix(value: string): boolean {
  return KNOWN_SECRET_PREFIXES.some((prefix) => value.startsWith(prefix));
}

export function acceptTokenSecret(value: string): boolean {
  return Boolean(value) && !isPublicStripeKey(value);
}

export function acceptEnvSecret(value: string, ctx: SecretMatchContext): boolean {
  if (!ctx.key || !value) {
    return false;
  }
  if (isPublicEnvVarName(ctx.key)) {
    return false;
  }
  if (
    isPlaceholderSecret(value) ||
    isPublicStripeKey(value) ||
    startsWithKnownTokenPrefix(value)
  ) {
    return false;
  }
  return true;
}

export function acceptDatabaseUrl(value: string, ctx: SecretMatchContext): boolean {
  if (!ctx.key || !value) {
    return false;
  }
  if (isPlaceholderSecret(value)) {
    return false;
  }
  return true;
}

export function acceptPasswordField(value: string, ctx: SecretMatchContext): boolean {
  if (!value || /\s/.test(value)) {
    return false;
  }
  if (isHtmlAttributeContext(ctx.content, ctx.matchIndex)) {
    return false;
  }
  if (
    isPlaceholderSecret(value) ||
    isPublicStripeKey(value) ||
    startsWithKnownTokenPrefix(value)
  ) {
    return false;
  }
  return true;
}

export function resolveProviderTokenLabel(match: RegExpExecArray): string {
  const token = match[1] ?? '';
  return token.startsWith('ghp_')
    ? 'GitHub token'
    : token.startsWith('sk-proj-')
      ? 'OpenAI API key'
      : 'Anthropic API key';
}

export const SECRET_RULES: readonly SecretRule[] = [
  {
    id: 'stripe-secret-key',
    kind: 'token',
    label: 'Stripe secret key',
    tokenPrefixes: ['sk_live_', 'sk_test_', 'rk_live_', 'rk_test_'],
    regex: STRIPE_SECRET_RE,
    accept: acceptTokenSecret,
    examples: {
      shouldDetect: [
        `const key = "${['sk', 'live', '1234567890abcdef'].join('_')}";`,
        `const key = "${['sk', 'test', '1234567890abcdef'].join('_')}";`,
        `const key = "${['rk', 'live', '1234567890abcdef'].join('_')}";`,
        `const key = "${['rk', 'test', '1234567890abcdef'].join('_')}";`,
      ],
      shouldIgnore: [
        `const pub = "${['pk', 'live', '1234567890abcdef'].join('_')}";`,
        `const pub = "${['pk', 'test', '1234567890abcdef'].join('_')}";`,
        `const short = "${['sk', 'live', '12345'].join('_')}";`,
      ],
    },
  },
  {
    id: 'google-api-key',
    kind: 'token',
    label: 'Google API key',
    tokenPrefixes: ['AIzaSy'],
    regex: GOOGLE_API_KEY_RE,
    accept: acceptTokenSecret,
    examples: {
      shouldDetect: [
        `const apiKey = "${['AIza', 'Sy', 'D1234567890abcdef1234567890abcdef'].join('')}";`,
      ],
      shouldIgnore: [`const shortKey = "${['AIza', 'Sy', 'Short123'].join('')}";`],
    },
  },
  {
    id: 'provider-tokens',
    kind: 'token',
    label: resolveProviderTokenLabel,
    tokenPrefixes: ['ghp_', 'sk-proj-', 'sk-ant-'],
    regex: PROVIDER_TOKEN_RE,
    accept: acceptTokenSecret,
    examples: {
      shouldDetect: [
        `const gh = "${['ghp', '_1234567890abcdef1234567890'].join('')}";`,
        `const oai = "${['sk-proj-', '1234567890abcdef1234'].join('')}";`,
        `const ant = "${['sk-ant-', '1234567890abcdef1234'].join('')}";`,
      ],
      shouldIgnore: [
        `const shortGh = "${['ghp', '_short123'].join('')}";`,
        'const normalText = "hello world";',
      ],
    },
  },
  {
    id: 'env-secret',
    kind: 'assignment',
    label: (match) => match[1] ?? 'ENV_SECRET',
    regex: ENV_SECRET_RE,
    extract: (match) => ({ key: match[1] ?? '', value: match[2] ?? '' }),
    accept: acceptEnvSecret,
    examples: {
      shouldDetect: [
        'JWT_SECRET = "superSecretJwtValue99"',
        'API_PRIVATE_KEY: "myPrivateKeyValue88"',
      ],
      shouldIgnore: [
        'NEXT_PUBLIC_API_SECRET = "publicValue123"',
        'VITE_APP_SECRET = "publicValue123"',
        'JWT_SECRET = "changeme"',
        `STRIPE_SECRET = "${['sk', 'live', '1234567890abcdef'].join('_')}"`,
      ],
    },
  },
  {
    id: 'database-url',
    kind: 'assignment',
    label: 'DATABASE_URL',
    regex: DATABASE_URL_RE,
    extract: (match) => ({ key: match[1] ?? '', value: match[2] ?? '' }),
    accept: acceptDatabaseUrl,
    mask: redactConnectionUri,
    examples: {
      shouldDetect: ['DATABASE_URL = "postgres://admin:mySecretPass@db.internal:5432/prod"'],
      shouldIgnore: [
        'DATABASE_URL = "<secret>"',
        'DATABASE_URL = "https://example.com"',
      ],
    },
  },
  {
    id: 'hardcoded-password',
    kind: 'assignment',
    label: (match) => `Hardcoded ${(match[1] ?? match[2] ?? 'password').toLowerCase()}`,
    regex: PASSWORD_FIELD_RE,
    extract: (match) => ({ key: match[1] ?? match[2] ?? 'password', value: match[3] ?? '' }),
    accept: acceptPasswordField,
    mask: redactPassword,
    examples: {
      shouldDetect: [
        'const cfg = { password: "Hunter2Example9" };',
        'const cfg = { senha: "SegredoForte99" };',
      ],
      shouldIgnore: [
        'const msg = { password: "Password must be at least 8 characters" };',
        '<input type="password" name="password: \'abcd1234\'" />',
        'const cfg = { password: "changeme" };',
      ],
    },
  },
];

export const KNOWN_SECRET_PREFIXES: readonly string[] = SECRET_RULES.flatMap(
  (rule) => rule.tokenPrefixes ?? [],
);
