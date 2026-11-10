import type { SanityIssue } from '../scanner/security-scan.js';

const KNOWN_TLS_CODES = new Set([
  'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'ERR_TLS_CERT_ALTNAME_INVALID',
]);

export function isTlsErrorCode(code: unknown): boolean {
  if (typeof code !== 'string' || !code) {
    return false;
  }
  return (
    KNOWN_TLS_CODES.has(code) ||
    code.startsWith('CERT_') ||
    code.startsWith('ERR_TLS_')
  );
}

export function inspectTlsError(code: string | undefined, route = '/'): SanityIssue {
  const safeCode = code ?? 'UNKNOWN_TLS_ERROR';
  return {
    kind: 'insecure_transport',
    severity: 'error',
    route,
    detail: `TLS connection failed: certificate verification failed (${safeCode})`,
  };
}

export function inspectHttpRedirect(
  statusCode: number,
  location: string | null | undefined,
  targetHost: string,
  route = '/',
): { ok: boolean; issue?: SanityIssue } {
  const isRedirect =
    statusCode === 301 ||
    statusCode === 302 ||
    statusCode === 307 ||
    statusCode === 308;

  if (isRedirect && location) {
    try {
      const parsedLocation = new URL(location, `http://${targetHost}`);
      const locHost = parsedLocation.hostname.toLowerCase();
      const tgtHost = targetHost.toLowerCase().split(':')[0]!;
      const isSameHost =
        locHost === tgtHost ||
        locHost === `www.${tgtHost}` ||
        `www.${locHost}` === tgtHost;

      if (parsedLocation.protocol === 'https:' && isSameHost) {
        return { ok: true };
      }
    } catch {
      // malformed location
    }
  }

  // 4xx e 5xx (ex: 400, 403, 426 Upgrade Required): silêncio
  if (statusCode >= 400) {
    return { ok: true };
  }

  return {
    ok: false,
    issue: {
      kind: 'insecure_transport',
      severity: 'error',
      route,
      statusCode,
      detail: 'Site serves content over unencrypted HTTP and does not redirect to HTTPS',
    },
  };
}

export function inspectHstsHeader(
  hstsHeader: string | null | undefined,
  route = '/',
): { ok: boolean; issue?: SanityIssue } {
  if (!hstsHeader) {
    return {
      ok: false,
      issue: {
        kind: 'insecure_transport',
        severity: 'warning',
        route,
        detail:
          'Strict-Transport-Security (HSTS) header is missing; browsers will not enforce HTTPS on future visits',
      },
    };
  }

  const maxAgeMatch = /\bmax-age\s*=\s*(\d+)/i.exec(hstsHeader);
  if (!maxAgeMatch || Number(maxAgeMatch[1]) <= 0) {
    return {
      ok: false,
      issue: {
        kind: 'insecure_transport',
        severity: 'warning',
        route,
        detail:
          'Strict-Transport-Security (HSTS) header is missing; browsers will not enforce HTTPS on future visits',
      },
    };
  }

  return { ok: true };
}
