export const PLACEHOLDER_VALUES: ReadonlySet<string> = new Set([
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

export const PUBLIC_STRIPE_PREFIXES = ['pk_live_', 'pk_test_'] as const;
export const PUBLIC_ENV_PREFIXES = ['NEXT_PUBLIC_', 'VITE_'] as const;
export const IGNORED_BUNDLED_MODULE_SUBSTRINGS = [
  'node_modules',
  'next/dist',
  'next_dist',
] as const;

export function isPlaceholderSecret(value: string): boolean {
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
  if (
    normalized.includes('your-') ||
    normalized.includes('your_') ||
    normalized.includes('changeme')
  ) {
    return true;
  }
  return false;
}

export function isPublicStripeKey(value: string): boolean {
  return PUBLIC_STRIPE_PREFIXES.some((prefix) => value.startsWith(prefix));
}

export function isPublicEnvVarName(varName: string): boolean {
  return PUBLIC_ENV_PREFIXES.some((prefix) => varName.startsWith(prefix));
}

export function isHtmlAttributeContext(content: string, matchIndex: number): boolean {
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

export function isIgnoredBundledModulePath(candidatePath: string): boolean {
  const lower = candidatePath.toLowerCase();
  return IGNORED_BUNDLED_MODULE_SUBSTRINGS.some((sub) => lower.includes(sub));
}
