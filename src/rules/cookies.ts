import type { SanityIssue } from '../scanner/security-scan.js';

const SESSION_TOKENS = new Set([
  'session',
  'sess',
  'sid',
  'auth',
  'token',
  'jwt',
  'id_token',
  'access_token',
  'refresh_token',
  'logged_in',
  'remember',
]);

const KNOWN_SESSION_PREFIXES = [
  '__host-',
  '__secure-',
  'connect.sid',
  'phpsessid',
  'jsessionid',
  'aspsessionid',
  'next-auth.',
];

const IGNORED_COOKIE_PREFIXES = [
  '_ga',
  '_gid',
  '_gat',
  '_clck',
  '_clsk',
  '_fbp',
  '_fbc',
  'theme',
  'dark_mode',
  'color_mode',
  'lang',
  'locale',
  'timezone',
  'cookie_consent',
  'cookies_accepted',
  'banner_dismissed',
];

export function isSessionCookieName(name: string): boolean {
  const lower = name.toLowerCase().trim();
  if (!lower) {
    return false;
  }

  // 1. Exclusão estrita de CSRF / XSRF antes de qualquer outra análise
  if (lower.includes('csrf') || lower.includes('xsrf')) {
    return false;
  }

  // 2. Exclusão de cookies conhecidos de analytics e preferências
  for (const ignored of IGNORED_COOKIE_PREFIXES) {
    if (lower === ignored || lower.startsWith(`${ignored}_`) || lower.startsWith(`${ignored}-`)) {
      return false;
    }
  }

  // 3. Prefixos canônicos de sessão
  for (const prefix of KNOWN_SESSION_PREFIXES) {
    if (lower.startsWith(prefix)) {
      return true;
    }
  }

  // Supabase auth tokens
  if (/^sb-.*-auth-token/.test(lower)) {
    return true;
  }

  // 4. Casamento por TOKENS delimitados por _, -, .
  const tokens = lower.split(/[_\-.]+/).filter(Boolean);
  for (const token of tokens) {
    if (SESSION_TOKENS.has(token)) {
      return true;
    }
  }

  return false;
}

export interface ParsedSetCookie {
  name: string;
  hasSecure: boolean;
  hasHttpOnly: boolean;
  sameSite: 'lax' | 'strict' | 'none' | null;
}

export function parseSetCookieHeader(raw: string): ParsedSetCookie | null {
  if (!raw || typeof raw !== 'string') {
    return null;
  }

  const parts = raw.split(';').map((p) => p.trim());
  const firstPart = parts[0];
  if (!firstPart) {
    return null;
  }

  const eqIdx = firstPart.indexOf('=');
  const name = (eqIdx !== -1 ? firstPart.slice(0, eqIdx) : firstPart).trim();
  if (!name) {
    return null;
  }

  let hasSecure = false;
  let hasHttpOnly = false;
  let sameSite: 'lax' | 'strict' | 'none' | null = null;

  for (let i = 1; i < parts.length; i++) {
    const attr = parts[i]!.toLowerCase();
    if (attr === 'secure') {
      hasSecure = true;
    } else if (attr === 'httponly') {
      hasHttpOnly = true;
    } else if (attr.startsWith('samesite=')) {
      const val = attr.slice('samesite='.length).trim();
      if (val === 'lax') {
        sameSite = 'lax';
      } else if (val === 'strict') {
        sameSite = 'strict';
      } else if (val === 'none') {
        sameSite = 'none';
      }
    }
  }

  return { name, hasSecure, hasHttpOnly, sameSite };
}

export function inspectSetCookie(
  rawCookie: string,
  isHttps: boolean,
  route = '/',
): SanityIssue[] {
  const parsed = parseSetCookieHeader(rawCookie);
  if (!parsed) {
    return [];
  }

  if (!isSessionCookieName(parsed.name)) {
    return [];
  }

  const issues: SanityIssue[] = [];
  const isSupabaseAuth = /^sb-.*-auth-token/i.test(parsed.name);

  // 1. Falta Secure sobre HTTPS (severidade: error)
  if (isHttps && !parsed.hasSecure) {
    issues.push({
      kind: 'insecure_cookie',
      severity: 'error',
      route,
      detail: `Session cookie "${parsed.name}" was set without the Secure attribute over HTTPS`,
    });
  }

  // 2. Falta HttpOnly (severidade: warning) — exceto Supabase SSR
  if (!isSupabaseAuth && !parsed.hasHttpOnly) {
    issues.push({
      kind: 'insecure_cookie',
      severity: 'warning',
      route,
      detail: `Session cookie "${parsed.name}" was set without the HttpOnly attribute`,
    });
  }

  // 3. SameSite=None sem Secure (severidade: warning)
  if (parsed.sameSite === 'none' && !parsed.hasSecure) {
    issues.push({
      kind: 'insecure_cookie',
      severity: 'warning',
      route,
      detail: `Session cookie "${parsed.name}" uses SameSite=None without the Secure attribute`,
    });
  }

  return issues;
}
