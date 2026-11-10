import type { SanityIssue } from '../scanner/security-scan.js';

export interface HeaderLookup {
  get(name: string): string | null;
}

export function inspectRootSecurityHeaders(
  headers: HeaderLookup,
  route = '/',
): SanityIssue[] {
  const issues: SanityIssue[] = [];

  // 1. X-Content-Type-Options: nosniff (suporta valores duplicados separados por vírgula)
  const rawXcto = headers.get('x-content-type-options') ?? '';
  const xctoTokens = rawXcto.split(',').map((s) => s.trim().toLowerCase());
  const hasValidXcto = xctoTokens.includes('nosniff');
  if (!hasValidXcto) {
    issues.push({
      kind: 'missing_security_headers',
      severity: 'warning',
      route,
      detail: 'Missing X-Content-Type-Options: nosniff header on root HTML response',
    });
  }

  // 2. Proteção contra framing (X-Frame-Options ou CSP frame-ancestors; suporta valores duplicados)
  const rawXfo = headers.get('x-frame-options') ?? '';
  const xfoTokens = rawXfo.split(',').map((s) => s.trim().toUpperCase());
  const hasValidXfo = xfoTokens.includes('DENY') || xfoTokens.includes('SAMEORIGIN');

  const csp = (headers.get('content-security-policy') ?? '').toLowerCase();
  const hasCspFrameAncestors = /\bframe-ancestors\b/.test(csp);

  if (!hasValidXfo && !hasCspFrameAncestors) {
    issues.push({
      kind: 'missing_security_headers',
      severity: 'warning',
      route,
      detail:
        'Missing anti-framing protection: neither X-Frame-Options (DENY or SAMEORIGIN) nor CSP frame-ancestors is present on root HTML response',
    });
  }

  return issues;
}
