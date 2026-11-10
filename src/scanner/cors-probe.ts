import type { SanityIssue } from './security-scan.js';

export const CORS_PROBE_ORIGIN = 'https://vibesane-cors-probe.invalid';
export const CORS_PROBE_PATHS = ['/', '/api'] as const;

export function isReflectedCredentialedCors(
  headers: Headers,
  probeOrigin: string,
): boolean {
  const allowOrigin = headers.get('access-control-allow-origin')?.trim();
  const allowCredentials = headers.get('access-control-allow-credentials')?.trim();

  if (!allowOrigin || !allowCredentials) {
    return false;
  }

  if (allowCredentials.toLowerCase() !== 'true') {
    return false;
  }

  return allowOrigin.toLowerCase() === probeOrigin.trim().toLowerCase();
}

export async function probeCors(
  baseOrigin: string,
  signal: AbortSignal,
  routeTimeoutMs: number,
  fetchFn: typeof fetch = fetch,
): Promise<SanityIssue[]> {
  const probeTasks = CORS_PROBE_PATHS.map(async (path): Promise<SanityIssue | null> => {
    let probeUrl: URL;
    try {
      probeUrl = new URL(path, baseOrigin);
    } catch {
      return null;
    }

    try {
      const hopSignal = AbortSignal.any([signal, AbortSignal.timeout(routeTimeoutMs)]);
      const res = await fetchFn(probeUrl.toString(), {
        method: 'GET',
        headers: {
          Origin: CORS_PROBE_ORIGIN,
          Cookie: 'vibesane_cors_probe=1',
        },
        redirect: 'manual',
        signal: hopSignal,
      });

      // Descarta o corpo sem ler
      await res.body?.cancel().catch(() => {});

      if (isReflectedCredentialedCors(res.headers, CORS_PROBE_ORIGIN)) {
        return {
          kind: 'insecure_cors',
          severity: 'error',
          route: path,
          detail: `Server reflects any Origin with credentials allowed on ${path} (Access-Control-Allow-Origin mirrors the request Origin and Access-Control-Allow-Credentials is true): any website can read this response with the user's cookies`,
        };
      }
    } catch {
      // Falha de rede, timeout ou cancelamento: fail-open silencioso
    }

    return null;
  });

  const results = await Promise.all(probeTasks);
  const issues: SanityIssue[] = [];
  for (const item of results) {
    if (item) {
      issues.push(item);
    }
  }

  return issues;
}
