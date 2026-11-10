import { performance } from 'node:perf_hooks';
import { readFileSync } from 'node:fs';
import {
  readBoundedTextBody,
  type RootHttpSnapshot,
} from './port-detector.js';
import { isTlsErrorCode } from '../rules/transport.js';

export function getVibesaneUserAgent(): string {
  try {
    const pkg = JSON.parse(
      readFileSync(new URL('../../package.json', import.meta.url), 'utf8'),
    ) as { version: string };
    return `vibesane/${pkg.version} (+https://github.com/cofresgoldsafe/vibesane)`;
  } catch {
    return 'vibesane/0.2.0 (+https://github.com/cofresgoldsafe/vibesane)';
  }
}

export function isSameHostOrWww(hostA: string, hostB: string): boolean {
  const a = hostA.toLowerCase();
  const b = hostB.toLowerCase();
  if (a === b) {
    return true;
  }
  return a === `www.${b}` || b === `www.${a}`;
}

export interface RemoteInitResult {
  ok: boolean;
  unreachableCode?: string;
  tlsError?: string;
  baseOrigin: string;
  initialUrl: string;
  finalUrl: string;
  redirectedFrom?: string;
  rootResponse?: RootHttpSnapshot;
  requestCount: number;
  rawHeaders?: Headers;
}

export async function initRemoteTarget(
  targetUrl: string,
  options: {
    routeTimeoutMs?: number;
    userAgent?: string;
  } = {},
): Promise<RemoteInitResult> {
  const timeoutMs = options.routeTimeoutMs ?? 4000;
  const userAgent = options.userAgent ?? getVibesaneUserAgent();

  const parsedInitial = new URL(targetUrl);
  const initialOrigin = parsedInitial.origin;
  const initialPath = `${parsedInitial.pathname || '/'}${parsedInitial.search || ''}`;

  let requestCount = 0;
  const start = performance.now();

  let res: Response;
  requestCount++;
  try {
    res = await fetch(new URL(initialPath, initialOrigin), {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        'User-Agent': userAgent,
        Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
      },
    });
  } catch (err: unknown) {
    const errObj = err as { code?: string; cause?: { code?: string; message?: string } };
    const errCode = errObj?.cause?.code ?? errObj?.code;

    if (isTlsErrorCode(errCode)) {
      return {
        ok: false,
        tlsError: errCode ?? 'TLS_VERIFICATION_FAILED',
        baseOrigin: initialOrigin,
        initialUrl: targetUrl,
        finalUrl: targetUrl,
        requestCount,
      };
    }

    return {
      ok: false,
      unreachableCode: errCode ?? (err instanceof Error ? err.name : 'ECONNFAILED'),
      baseOrigin: initialOrigin,
      initialUrl: targetUrl,
      finalUrl: targetUrl,
      requestCount,
    };
  }

  let finalOrigin = initialOrigin;
  let finalPath = initialPath;
  let redirectedFrom: string | undefined;
  let finalRes = res;
  let headersElapsedMs = Math.round(performance.now() - start);

  const isRedirect =
    res.status === 301 ||
    res.status === 302 ||
    res.status === 303 ||
    res.status === 307 ||
    res.status === 308;

  const location = res.headers.get('location');

  if (isRedirect && location) {
    let targetLoc: URL | null = null;
    try {
      targetLoc = new URL(location, initialOrigin);
    } catch {
      targetLoc = null;
    }

    if (targetLoc) {
      const isHttpToHttps =
        parsedInitial.protocol === 'http:' &&
        targetLoc.protocol === 'https:' &&
        isSameHostOrWww(targetLoc.hostname, parsedInitial.hostname);

      const isWwwSwitch =
        parsedInitial.protocol === targetLoc.protocol &&
        isSameHostOrWww(targetLoc.hostname, parsedInitial.hostname);

      const isSameOriginRedirect = targetLoc.origin === initialOrigin;

      if (isHttpToHttps || isWwwSwitch || isSameOriginRedirect) {
        requestCount++;
        try {
          const hopStart = performance.now();
          const followRes = await fetch(targetLoc.href, {
            method: 'GET',
            redirect: 'manual',
            signal: AbortSignal.timeout(timeoutMs),
            headers: {
              'User-Agent': userAgent,
              Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
            },
          });
          headersElapsedMs = Math.round(performance.now() - hopStart);
          finalRes = followRes;
          finalOrigin = targetLoc.origin;
          finalPath = `${targetLoc.pathname || '/'}${targetLoc.search || ''}`;
          if (finalOrigin !== initialOrigin) {
            redirectedFrom = initialOrigin;
          }
        } catch (err: unknown) {
          const errObj = err as { code?: string; cause?: { code?: string; message?: string } };
          const errCode = errObj?.cause?.code ?? errObj?.code;
          if (isTlsErrorCode(errCode)) {
            return {
              ok: false,
              tlsError: errCode ?? 'TLS_VERIFICATION_FAILED',
              baseOrigin: targetLoc.origin,
              initialUrl: targetUrl,
              finalUrl: targetLoc.href,
              requestCount,
            };
          }
          // Se o follow falhar por outra razão não-TLS, mantém a resposta original do redirect
        }
      }
    }
  }

  const { body, truncated, truncatedReason } = await readBoundedTextBody(
    finalRes,
    1024 * 1024,
    2000,
  );

  const rootSnapshot: RootHttpSnapshot = {
    path: finalPath,
    statusCode: finalRes.status,
    contentType: finalRes.headers.get('content-type') ?? '',
    location: finalRes.headers.get('location') ?? undefined,
    body,
    headersElapsedMs,
    truncated,
    truncatedReason,
  };

  return {
    ok: true,
    baseOrigin: finalOrigin,
    initialUrl: targetUrl,
    finalUrl: new URL(finalPath, finalOrigin).href,
    redirectedFrom,
    rootResponse: rootSnapshot,
    requestCount,
    rawHeaders: finalRes.headers,
  };
}
