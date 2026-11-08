import crypto from 'node:crypto';
import type { SanityIssue } from './security-scan.js';
import { scanSecrets } from './security-scan.js';
import {
  readBoundedTextBody,
  MAX_BODY_BYTES,
  DEFAULT_BODY_READ_TIMEOUT_MS,
} from './port-detector.js';

export const ADMIN_PROBE_PATHS = ['/admin', '/dashboard', '/debug'] as const;
export const VIBESANE_PATH_MARKER = '__VIBESANE_PATH__';

const NONCE_ATTR_RE = /\s+nonce\s*=\s*(?:'[^']*'|\x22[^\x22]*\x22|[^\s>]+)/gi;
const LOOKS_LIKE_LOGIN_RE =
  /<input\b[^>]*\btype\s*=\s*(?:'password'|\x22password\x22|password(?=[\s/>]|$))/i;

export function maskOwnPath(body: string, path: string): string {
  if (!body || !path || path === '/') {
    return body;
  }

  let masked = body.replaceAll(path, VIBESANE_PATH_MARKER);
  const encoded = encodeURI(path);
  if (encoded !== path) {
    masked = masked.replaceAll(encoded, VIBESANE_PATH_MARKER);
  }
  return masked;
}

export function normalizeHtmlForComparison(body: string): string {
  if (!body) {
    return '';
  }
  return body
    .replace(NONCE_ATTR_RE, '')
    .replace(/\s+/g, ' ')
    .trim();
}

export function looksLikeLoginPage(body: string): boolean {
  if (!body) {
    return false;
  }
  return LOOKS_LIKE_LOGIN_RE.test(body);
}

export function isSameAsFallback(
  candidateBody: string,
  fallbackBodies: string[],
): boolean {
  const normalizedCandidate = normalizeHtmlForComparison(candidateBody);
  if (!normalizedCandidate) {
    return false;
  }

  for (const fallback of fallbackBodies) {
    if (!fallback || fallback.trim() === '') {
      continue;
    }
    if (normalizedCandidate === normalizeHtmlForComparison(fallback)) {
      return true;
    }
  }

  return false;
}

interface ProbeRouteResult {
  path: string;
  body: string;
}

export async function probeAdminRoutes(
  baseOrigin: string,
  rootBody: string,
  signal: AbortSignal,
  routeTimeoutMs: number,
): Promise<SanityIssue[]> {
  const randomSuffix = crypto.randomBytes(4).toString('hex');
  const missingPath = `/vibesane-missing-${randomSuffix}`;

  const fetchProbeRoute = async (
    path: string,
  ): Promise<ProbeRouteResult | null> => {
    let probeUrl: URL;
    try {
      probeUrl = new URL(path, baseOrigin);
    } catch {
      return null;
    }

    try {
      const hopSignal = AbortSignal.any([
        signal,
        AbortSignal.timeout(routeTimeoutMs),
      ]);
      const res = await fetch(probeUrl.toString(), {
        method: 'GET',
        redirect: 'manual',
        signal: hopSignal,
        credentials: 'omit',
      });

      if (res.status !== 200) {
        await res.body?.cancel().catch(() => {});
        return null;
      }

      const snap = await readBoundedTextBody(
        res,
        MAX_BODY_BYTES,
        DEFAULT_BODY_READ_TIMEOUT_MS,
      );

      if (snap.truncated) {
        return null;
      }

      return {
        path,
        body: snap.body,
      };
    } catch {
      return null;
    }
  };

  const allPaths = [missingPath, ...ADMIN_PROBE_PATHS];
  const results = await Promise.all(
    allPaths.map((probePath) => fetchProbeRoute(probePath)),
  );

  const missingResult = results[0];
  const adminResults = results.slice(1);

  const fallbackBodies: string[] = [];
  if (rootBody && rootBody.trim() !== '') {
    fallbackBodies.push(rootBody);
  }
  if (missingResult && missingResult.body.trim() !== '') {
    fallbackBodies.push(maskOwnPath(missingResult.body, missingResult.path));
  }

  const issues: SanityIssue[] = [];

  for (const item of adminResults) {
    if (!item) {
      continue;
    }

    const body = item.body;
    if (body.trim() === '') {
      continue;
    }

    const maskedBody = maskOwnPath(body, item.path);
    if (isSameAsFallback(maskedBody, fallbackBodies)) {
      continue;
    }

    if (looksLikeLoginPage(body)) {
      continue;
    }

    issues.push({
      kind: 'unauthenticated_admin_route',
      severity: 'warning',
      route: item.path,
      detail: `GET ${item.path} answered 200 with its own content without credentials (no redirect, 401/403, login form or SPA fallback); if this area is meant to be private, protect it on the server`,
    });

    if (body.length > 0) {
      issues.push(...scanSecrets(body, item.path));
    }
  }

  return issues;
}
