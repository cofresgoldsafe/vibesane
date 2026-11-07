import { performance } from 'node:perf_hooks';
import {
  assertValidTimeout,
  MAX_BODY_BYTES,
  MAX_SCRIPT_BODY_BYTES,
  DEFAULT_BODY_READ_TIMEOUT_MS,
  DEFAULT_SCRIPT_BODY_READ_TIMEOUT_MS,
  readBoundedTextBody,
  type LoopbackHost,
  type RootHttpSnapshot,
  type TruncatedReason,
} from './port-detector.js';
import {
  detectMaskedError,
  extractNextErrorInfo,
  extractViteErrorInfo,
  scanSecrets,
  sanitizeErrorSnippet,
  stripViteTimestampQuery,
  type SanityIssue,
} from './security-scan.js';
import { checkScriptSyntax } from './syntax-check.js';

export const DEFAULT_SCAN_BUDGET_MS = 2500;
export const DEFAULT_ROUTE_TIMEOUT_MS = 2000;
export const DEFAULT_SLOW_ROUTE_MS = 1500;
export const DEFAULT_MAX_ROUTES = 10;
export const DEFAULT_MAX_SCRIPTS = 5;
export const DEFAULT_MAX_CONCURRENCY = 4;
export const MAX_REDIRECTS = 3;

export interface RouteScanItem {
  path: string;
  statusCode?: number;
  contentType?: string;
  headersElapsedMs?: number;
  truncated?: boolean;
  skipped?: boolean;
}

export interface SanityScanOptions {
  scanBudgetMs?: number;
  routeTimeoutMs?: number;
  slowRouteMs?: number;
  maxRoutes?: number;
  maxScripts?: number;
  maxConcurrency?: number;
}

export interface SanityScanSummary {
  routes: RouteScanItem[];
  scannedScripts: string[];
  skippedRoutes: string[];
  issues: SanityIssue[];
}

const ANCHOR_HREF_RE = /<a\b[^>]*?\bhref\s*=\s*(?:["']([^"']+)["']|([^\s>]+))/gi;
const SCRIPT_SRC_RE = /<script\b[^>]*?\bsrc\s*=\s*(?:["']([^"']+)["']|([^\s>]+))/gi;
const STATIC_IMPORT_RE = /(?:import|export)\s+(?:[^"'\r\n;]{1,256}?\s+from\s+)?["']([^"'\r\n]+)["']/g;
const DYNAMIC_IMPORT_RE = /import\s*\(\s*["']([^"']+)["']\s*\)/g;
const SCRIPT_TAG_RE = /<script\b([^>]*)>/gi;
const STANDARD_SCRIPT_TYPES = new Set([
  '',
  'module',
  'text/javascript',
  'application/javascript',
  'application/ecmascript',
]);

function extractNonStandardTypeScriptPaths(html: string, baseOrigin: string): Set<string> {
  const result = new Set<string>();
  if (!html) {
    return result;
  }
  let baseUrl: URL;
  try {
    baseUrl = new URL(baseOrigin);
  } catch {
    return result;
  }

  SCRIPT_TAG_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SCRIPT_TAG_RE.exec(html)) !== null) {
    const attrs = match[1] ?? '';
    const srcMatch = /\bsrc\s*=\s*(?:["']([^"']+)["']|([^\s>]+))/i.exec(attrs);
    if (!srcMatch) {
      continue;
    }
    const rawSrc = (srcMatch[1] ?? srcMatch[2] ?? '').trim();
    if (!rawSrc) {
      continue;
    }

    let resolved: URL;
    try {
      resolved = new URL(rawSrc, baseUrl);
    } catch {
      continue;
    }
    if (!isSameLocalOrigin(resolved, baseUrl)) {
      continue;
    }

    const normalized = stripViteTimestampQuery(`${resolved.pathname}${resolved.search}`);

    const typeMatch = /\btype\s*=\s*(?:["']([^"']+)["']|([^\s>]+))/i.exec(attrs);
    const rawType = (typeMatch ? (typeMatch[1] ?? typeMatch[2] ?? '') : '').trim().toLowerCase();

    if (!STANDARD_SCRIPT_TYPES.has(rawType)) {
      result.add(normalized);
    }
  }

  return result;
}
const NEXT_FLIGHT_CHUNK_RE =
  /(?<=^|[^\w\\/])\\?["']((?:(?:\/_next\/)?static\/chunks\/)[A-Za-z0-9_./@%+()-]+\.js)\\?["']/g;

const IGNORED_HREF_PREFIXES = ['#', 'mailto:', 'tel:', 'javascript:', 'data:'] as const;
const IGNORED_ROUTE_PATH_PREFIXES = ['/_next/', '/@vite/', '/node_modules/'] as const;
const STATIC_ASSET_EXT_RE =
  /\.(?:css|js|mjs|cjs|ts|tsx|jsx|png|jpg|jpeg|gif|svg|webp|ico|woff|woff2|ttf|eot|map|pdf|zip|mp4|webm)$/i;
const IGNORED_MODULE_EXT_RE = /\.(?:css|svg|png|json)$/i;

const EXCLUDED_SCRIPT_SUBSTRINGS = [
  '/node_modules/',
  'node_modules_',
  'next_dist',
  '/@vite/',
  '/@react-refresh',
  'webpack',
  'main-app',
  'polyfill',
  'react-refresh',
  'framework-',
  'turbopack',
  '%5bturbopack%5d',
  '_buildmanifest',
  '_ssgmanifest',
] as const;

const PRIORITY_SCRIPT_SUBSTRINGS = [
  '/src/',
  'app/page',
  'app/layout',
  '/_next/static/chunks/app/',
  '/_next/static/chunks/pages/',
  '/pages/',
] as const;

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]']);

export function isSameLocalOrigin(candidate: URL, base: URL): boolean {
  if (candidate.origin === base.origin) {
    return true;
  }
  return (
    candidate.protocol === base.protocol &&
    candidate.port === base.port &&
    LOOPBACK_HOSTNAMES.has(candidate.hostname) &&
    LOOPBACK_HOSTNAMES.has(base.hostname)
  );
}

export function isExcludedFrameworkScript(pathOrUrl: string): boolean {
  const lower = pathOrUrl.toLowerCase();
  return EXCLUDED_SCRIPT_SUBSTRINGS.some((token) => lower.includes(token));
}

export function getScriptPriority(pathOrUrl: string): 1 | 2 {
  for (const token of PRIORITY_SCRIPT_SUBSTRINGS) {
    if (pathOrUrl.includes(token)) {
      return 1;
    }
  }
  return 2;
}

export function extractInternalLinks(
  html: string,
  baseOrigin: string,
  maxSubRoutes: number,
): string[] {
  if (!html || maxSubRoutes <= 0) {
    return [];
  }

  let baseUrl: URL;
  try {
    baseUrl = new URL(baseOrigin);
  } catch {
    return [];
  }

  const results: string[] = [];
  const seen = new Set<string>(['/']);

  ANCHOR_HREF_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = ANCHOR_HREF_RE.exec(html)) !== null) {
    if (results.length >= maxSubRoutes) {
      break;
    }

    const rawHref = (match[1] ?? match[2] ?? '').trim();
    if (!rawHref) {
      continue;
    }

    const lowerHref = rawHref.toLowerCase();
    if (IGNORED_HREF_PREFIXES.some((prefix) => lowerHref.startsWith(prefix))) {
      continue;
    }

    let resolved: URL;
    try {
      resolved = new URL(rawHref, baseUrl);
    } catch {
      continue;
    }

    if (!isSameLocalOrigin(resolved, baseUrl)) {
      continue;
    }

    const pathname = resolved.pathname;
    if (IGNORED_ROUTE_PATH_PREFIXES.some((prefix) => pathname.startsWith(prefix))) {
      continue;
    }

    if (STATIC_ASSET_EXT_RE.test(pathname)) {
      continue;
    }

    const normalized = `${pathname}${resolved.search}`;
    if (seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    results.push(normalized);
  }

  return results;
}

export function extractCandidateScripts(
  html: string,
  baseOrigin: string,
  maxScripts: number,
): string[] {
  if (!html || maxScripts <= 0) {
    return [];
  }

  let baseUrl: URL;
  try {
    baseUrl = new URL(baseOrigin);
  } catch {
    return [];
  }

  const candidates: Array<{ path: string; priority: 1 | 2; index: number }> = [];
  const seen = new Set<string>();

  SCRIPT_SRC_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  let idx = 0;
  while ((match = SCRIPT_SRC_RE.exec(html)) !== null) {
    const rawSrc = (match[1] ?? match[2] ?? '').trim();
    if (!rawSrc) {
      continue;
    }

    let resolved: URL;
    try {
      resolved = new URL(rawSrc, baseUrl);
    } catch {
      continue;
    }

    if (!isSameLocalOrigin(resolved, baseUrl)) {
      continue;
    }

    const normalized = stripViteTimestampQuery(`${resolved.pathname}${resolved.search}`);
    if (seen.has(normalized)) {
      continue;
    }

    if (isExcludedFrameworkScript(normalized)) {
      continue;
    }

    seen.add(normalized);
    candidates.push({
      path: normalized,
      priority: getScriptPriority(normalized),
      index: idx++,
    });
  }

  NEXT_FLIGHT_CHUNK_RE.lastIndex = 0;
  while ((match = NEXT_FLIGHT_CHUNK_RE.exec(html)) !== null) {
    const rawChunk = (match[1] ?? '').trim();
    if (!rawChunk) {
      continue;
    }

    const chunkPath = rawChunk.startsWith('/_next/')
      ? rawChunk
      : `/_next/${rawChunk}`;

    let resolved: URL;
    try {
      resolved = new URL(chunkPath, baseUrl);
    } catch {
      continue;
    }

    if (!isSameLocalOrigin(resolved, baseUrl)) {
      continue;
    }

    const normalized = stripViteTimestampQuery(`${resolved.pathname}${resolved.search}`);
    if (seen.has(normalized)) {
      continue;
    }

    if (isExcludedFrameworkScript(normalized)) {
      continue;
    }

    seen.add(normalized);
    candidates.push({
      path: normalized,
      priority: getScriptPriority(normalized),
      index: idx++,
    });
  }

  candidates.sort((a, b) => {
    if (a.priority !== b.priority) {
      return a.priority - b.priority;
    }
    return a.index - b.index;
  });

  return candidates.slice(0, maxScripts).map((c) => c.path);
}

export function selectScriptsToFetch(
  input: string | readonly string[],
  baseOriginOrMaxScripts: string | number = 'http://localhost:3000',
  maxScripts: number = DEFAULT_MAX_SCRIPTS,
): string[] {
  if (typeof input === 'string') {
    const baseOrigin =
      typeof baseOriginOrMaxScripts === 'string'
        ? baseOriginOrMaxScripts
        : 'http://localhost:3000';
    const limit =
      typeof baseOriginOrMaxScripts === 'number'
        ? baseOriginOrMaxScripts
        : maxScripts;
    return extractCandidateScripts(input, baseOrigin, limit);
  }

  const limit =
    typeof baseOriginOrMaxScripts === 'number'
      ? baseOriginOrMaxScripts
      : maxScripts;
  if (limit <= 0) {
    return [];
  }

  const candidates: Array<{ path: string; priority: 1 | 2; index: number }> = [];
  const seen = new Set<string>();
  let idx = 0;

  for (const raw of input) {
    const trimmed = stripViteTimestampQuery(raw.trim());
    if (!trimmed || seen.has(trimmed) || isExcludedFrameworkScript(trimmed)) {
      continue;
    }
    seen.add(trimmed);
    candidates.push({
      path: trimmed,
      priority: getScriptPriority(trimmed),
      index: idx++,
    });
  }

  candidates.sort((a, b) => {
    if (a.priority !== b.priority) {
      return a.priority - b.priority;
    }
    return a.index - b.index;
  });

  return candidates.slice(0, limit).map((c) => c.path);
}

export function extractModuleImports(
  jsContent: string,
  scriptPath: string,
  baseOrigin: string,
): string[] {
  if (!jsContent) {
    return [];
  }

  let baseUrl: URL;
  let scriptUrl: URL;
  try {
    baseUrl = new URL(baseOrigin);
    scriptUrl = new URL(scriptPath, baseUrl);
  } catch {
    return [];
  }

  const specifiers: string[] = [];
  let match: RegExpExecArray | null;

  STATIC_IMPORT_RE.lastIndex = 0;
  while ((match = STATIC_IMPORT_RE.exec(jsContent)) !== null) {
    if (match[1]) {
      specifiers.push(match[1].trim());
    }
  }

  DYNAMIC_IMPORT_RE.lastIndex = 0;
  while ((match = DYNAMIC_IMPORT_RE.exec(jsContent)) !== null) {
    if (match[1]) {
      specifiers.push(match[1].trim());
    }
  }

  const results: string[] = [];
  const seen = new Set<string>();

  for (const spec of specifiers) {
    if (
      !spec.startsWith('/src/') &&
      !spec.startsWith('./') &&
      !spec.startsWith('../')
    ) {
      continue;
    }

    let resolved: URL;
    try {
      resolved = new URL(spec, scriptUrl);
    } catch {
      continue;
    }

    if (!isSameLocalOrigin(resolved, baseUrl)) {
      continue;
    }

    if (IGNORED_MODULE_EXT_RE.test(resolved.pathname)) {
      continue;
    }

    const normalized = stripViteTimestampQuery(`${resolved.pathname}${resolved.search}`);
    if (isExcludedFrameworkScript(normalized) || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    results.push(normalized);
  }

  return results;
}

export function formatTruncatedBodyMessage(
  route: string,
  isScript: boolean,
  reason: TruncatedReason | null | undefined,
  maxBytes: number,
  timeoutMs: number,
): string {
  const resourceLabel = isScript ? `script ${route}` : route;
  const limitMb = Math.round(maxBytes / (1024 * 1024));

  if (reason === 'timeout') {
    return `response body truncated on ${resourceLabel} (read timeout after ${timeoutMs} ms)`;
  }
  if (reason === 'error') {
    return `response body truncated on ${resourceLabel} (stream error)`;
  }
  return `response body truncated on ${resourceLabel} (exceeded ${limitMb} MB limit)`;
}

export async function fetchSameOriginHop(
  baseUrl: string,
  initialPath: string,
  signal: AbortSignal,
  routeTimeoutMs: number,
  followRedirects = true,
  maxBytes: number = MAX_BODY_BYTES,
  bodyTimeoutMs: number = DEFAULT_BODY_READ_TIMEOUT_MS,
): Promise<RootHttpSnapshot> {
  const base = new URL(baseUrl);
  let currentUrl = new URL(initialPath, base);
  let hops = 0;

  while (true) {
    const hopSignal = AbortSignal.any([signal, AbortSignal.timeout(routeTimeoutMs)]);
    const hopStart = performance.now();
    const res = await fetch(currentUrl.toString(), {
      method: 'GET',
      redirect: 'manual',
      signal: hopSignal,
    });
    const headersElapsedMs = Math.max(0, Math.round(performance.now() - hopStart));
    const statusCode = res.status;
    const contentType = res.headers.get('content-type') ?? '';
    const location = res.headers.get('location') ?? undefined;

    if (
      followRedirects &&
      REDIRECT_STATUS_CODES.has(statusCode) &&
      location !== undefined
    ) {
      let nextUrl: URL | null = null;
      try {
        nextUrl = new URL(location, currentUrl);
      } catch {
        nextUrl = null;
      }

      if (nextUrl && isSameLocalOrigin(nextUrl, base)) {
        await res.body?.cancel().catch(() => {});
        if (hops >= MAX_REDIRECTS) {
          throw new Error(`Exceeded maximum redirects (${MAX_REDIRECTS}) on ${initialPath}`);
        }
        currentUrl = new URL(`${nextUrl.pathname}${nextUrl.search}`, base);
        hops += 1;
        continue;
      }
    }

    const { body, truncated, truncatedReason } = await readBoundedTextBody(
      res,
      maxBytes,
      bodyTimeoutMs,
    );

    return {
      path: initialPath,
      statusCode,
      contentType,
      location,
      body,
      headersElapsedMs,
      truncated,
      truncatedReason,
    };
  }
}

function isHtmlLike(contentType: string, body: string): boolean {
  const lower = contentType.toLowerCase();
  if (lower.includes('text/html') || lower.includes('application/xhtml+xml')) {
    return true;
  }
  const trimmed = body.trimStart();
  return (
    trimmed.startsWith('<!DOCTYPE') ||
    trimmed.startsWith('<!doctype') ||
    trimmed.startsWith('<html') ||
    trimmed.startsWith('<HTML') ||
    trimmed.startsWith('<')
  );
}

export async function runSanityScan(
  host: LoopbackHost,
  port: number,
  rootResponse: RootHttpSnapshot,
  options: SanityScanOptions = {},
): Promise<SanityScanSummary> {
  const scanBudgetMs = options.scanBudgetMs ?? DEFAULT_SCAN_BUDGET_MS;
  const routeTimeoutMs = options.routeTimeoutMs ?? DEFAULT_ROUTE_TIMEOUT_MS;
  const slowRouteMs = options.slowRouteMs ?? DEFAULT_SLOW_ROUTE_MS;
  const maxRoutes = options.maxRoutes ?? DEFAULT_MAX_ROUTES;
  const maxScripts = options.maxScripts ?? DEFAULT_MAX_SCRIPTS;
  const maxConcurrency = options.maxConcurrency ?? DEFAULT_MAX_CONCURRENCY;

  assertValidTimeout(scanBudgetMs, 'scanBudgetMs');
  assertValidTimeout(routeTimeoutMs, 'routeTimeoutMs');
  assertValidTimeout(slowRouteMs, 'slowRouteMs');

  if (!Number.isInteger(maxRoutes) || maxRoutes < 1) {
    throw new RangeError(`Invalid maxRoutes "${maxRoutes}": expected integer >= 1`);
  }
  if (!Number.isInteger(maxScripts) || maxScripts < 0) {
    throw new RangeError(`Invalid maxScripts "${maxScripts}": expected integer >= 0`);
  }
  if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1) {
    throw new RangeError(`Invalid maxConcurrency "${maxConcurrency}": expected integer >= 1`);
  }

  const fetchHost = host === '::1' ? '[::1]' : '127.0.0.1';
  const baseOrigin = `http://${fetchHost}:${port}`;
  const baseUrlObj = new URL(baseOrigin);

  const routes: RouteScanItem[] = [];
  const scannedScripts: string[] = [];
  const skippedRoutes: string[] = [];
  const issues: SanityIssue[] = [];
  const crawlStart = performance.now();

  const budgetController = new AbortController();
  const budgetTimer = setTimeout(() => {
    budgetController.abort();
  }, scanBudgetMs);

  try {
    let finalRoot: RootHttpSnapshot = rootResponse;

    if (
      REDIRECT_STATUS_CODES.has(rootResponse.statusCode) &&
      rootResponse.location !== undefined
    ) {
      let redirectTarget: URL | null = null;
      try {
        redirectTarget = new URL(rootResponse.location, baseUrlObj);
      } catch {
        redirectTarget = null;
      }

      if (redirectTarget && isSameLocalOrigin(redirectTarget, baseUrlObj)) {
        const nextPath = `${redirectTarget.pathname}${redirectTarget.search}`;
        try {
          const followed = await fetchSameOriginHop(
            baseOrigin,
            nextPath,
            budgetController.signal,
            routeTimeoutMs,
            true,
          );
          finalRoot = {
            ...followed,
            path: '/',
          };
        } catch (err: unknown) {
          if (!budgetController.signal.aborted) {
            const isTimeout =
              err instanceof Error &&
              (err.name === 'TimeoutError' || err.name === 'AbortError');
            if (isTimeout) {
              issues.push({
                kind: 'slow_route',
                severity: 'warning',
                route: '/',
                elapsedMs: routeTimeoutMs,
                detail: `slow route / -> ${redirectTarget.pathname} (did not respond within ${routeTimeoutMs}ms - may be dev server compilation; re-run to confirm)`,
              });
            } else {
              issues.push({
                kind: 'http_error',
                severity: 'error',
                route: '/',
                detail: 'Connection failed on route /',
              });
            }
          }
        }
      }
    }

    routes.push({
      path: '/',
      statusCode: finalRoot.statusCode,
      contentType: finalRoot.contentType,
      headersElapsedMs: finalRoot.headersElapsedMs,
      truncated: finalRoot.truncated,
    });

    if (finalRoot.truncated) {
      issues.push({
        kind: 'truncated_body',
        severity: 'warning',
        route: '/',
        detail: formatTruncatedBodyMessage(
          '/',
          false,
          finalRoot.truncatedReason,
          MAX_BODY_BYTES,
          DEFAULT_BODY_READ_TIMEOUT_MS,
        ),
      });
    }

    const isFinalRootRedirect =
      finalRoot.statusCode >= 300 && finalRoot.statusCode < 400;

    if (finalRoot.statusCode >= 400) {
      const structured =
        extractNextErrorInfo(finalRoot.body, '/') ??
        extractViteErrorInfo(finalRoot.body, '/');
      if (structured) {
        issues.push({
          kind: 'http_error',
          severity: 'error',
          route: '/',
          statusCode: finalRoot.statusCode,
          detail: `HTTP ${finalRoot.statusCode} on route / (${structured.summary})`,
          maskedSnippet: structured.summary,
          ...(structured.codeFrame ? { codeFrame: structured.codeFrame } : {}),
        });
      } else {
        const masked = isHtmlLike(finalRoot.contentType, finalRoot.body)
          ? detectMaskedError(finalRoot.body, '/')
          : [];
        const snippet = masked[0]?.maskedSnippet;
        const codeFrame = masked[0]?.codeFrame;
        issues.push({
          kind: 'http_error',
          severity: 'error',
          route: '/',
          statusCode: finalRoot.statusCode,
          detail: snippet
            ? `HTTP ${finalRoot.statusCode} on route / (${snippet})`
            : `HTTP ${finalRoot.statusCode} on route /`,
          ...(snippet ? { maskedSnippet: snippet } : {}),
          ...(codeFrame ? { codeFrame } : {}),
        });
      }
    } else if (!isFinalRootRedirect && isHtmlLike(finalRoot.contentType, finalRoot.body)) {
      issues.push(...detectMaskedError(finalRoot.body, '/'));
    }

    if (!isFinalRootRedirect && finalRoot.body.length > 0) {
      issues.push(...scanSecrets(finalRoot.body, '/'));
    }

    const rootHasViteClient = finalRoot.body.includes('/@vite/client');
    const nonStandardTypeScripts = extractNonStandardTypeScriptPaths(
      finalRoot.body,
      baseOrigin,
    );

    const candidateScripts = isFinalRootRedirect
      ? []
      : extractCandidateScripts(
          finalRoot.body,
          baseOrigin,
          maxScripts,
        );
    const subRoutes = isFinalRootRedirect
      ? []
      : extractInternalLinks(
          finalRoot.body,
          baseOrigin,
          Math.max(0, maxRoutes - 1),
        );

    const scheduledScripts = new Set<string>(candidateScripts);
    const subRouteOutcomes = new Map<string, RouteScanItem>();

    type TaskFn = () => Promise<void>;
    const taskQueue: TaskFn[] = [];
    let activeCount = 0;
    let resolvePool!: () => void;
    const poolDone = new Promise<void>((resolve) => {
      resolvePool = resolve;
    });

    const pump = (): void => {
      if (taskQueue.length === 0 && activeCount === 0) {
        resolvePool();
        return;
      }
      while (activeCount < maxConcurrency && taskQueue.length > 0) {
        const task = taskQueue.shift()!;
        activeCount += 1;
        task()
          .catch(() => {})
          .finally(() => {
            activeCount -= 1;
            pump();
          });
      }
    };

    const enqueueScriptTask = (scriptPath: string, isModule = false): void => {
      const cleanScriptPath = stripViteTimestampQuery(scriptPath);
      taskQueue.push(async () => {
        if (budgetController.signal.aborted) {
          return;
        }
        try {
          const snap = await fetchSameOriginHop(
            baseOrigin,
            scriptPath,
            budgetController.signal,
            routeTimeoutMs,
            true,
            MAX_SCRIPT_BODY_BYTES,
            DEFAULT_SCRIPT_BODY_READ_TIMEOUT_MS,
          );
          scannedScripts.push(cleanScriptPath);

          if (snap.truncated) {
            issues.push({
              kind: 'truncated_body',
              severity: 'warning',
              route: cleanScriptPath,
              detail: formatTruncatedBodyMessage(
                cleanScriptPath,
                true,
                snap.truncatedReason,
                MAX_SCRIPT_BODY_BYTES,
                DEFAULT_SCRIPT_BODY_READ_TIMEOUT_MS,
              ),
            });
          }

          if (snap.statusCode >= 400) {
            const structured = extractViteErrorInfo(snap.body, cleanScriptPath);
            const snippet = structured ? structured.summary : sanitizeErrorSnippet(snap.body);
            let detail: string;
            if (snippet && snippet.startsWith(cleanScriptPath)) {
              detail = `HTTP ${snap.statusCode} on script ${snippet}`;
            } else if (snippet) {
              detail = `HTTP ${snap.statusCode} on script ${cleanScriptPath}: ${snippet}`;
            } else {
              detail = `HTTP ${snap.statusCode} on script ${cleanScriptPath}`;
            }
            issues.push({
              kind: 'http_error',
              severity: 'error',
              route: cleanScriptPath,
              statusCode: snap.statusCode,
              detail,
              ...(snippet ? { maskedSnippet: snippet } : {}),
              ...(structured?.codeFrame ? { codeFrame: structured.codeFrame } : {}),
            });
          }

          if (snap.body.length > 0) {
            issues.push(...scanSecrets(snap.body, cleanScriptPath));
          }

          if (
            snap.statusCode >= 200 &&
            snap.statusCode < 300 &&
            !snap.truncated &&
            !cleanScriptPath.startsWith('/_next/') &&
            !cleanScriptPath.includes('node_modules') &&
            !nonStandardTypeScripts.has(cleanScriptPath)
          ) {
            const elapsedNow = performance.now() - crawlStart;
            const remainingMs = Math.max(100, Math.round(scanBudgetMs - elapsedNow));
            const syntaxIssue = await checkScriptSyntax({
              code: snap.body,
              route: cleanScriptPath,
              isModule,
              contentType: snap.contentType,
              signal: budgetController.signal,
              timeoutMs: Math.min(2000, remainingMs),
              rootHasViteClient,
            });
            if (syntaxIssue) {
              issues.push(syntaxIssue);
            }
          }

          if (
            !budgetController.signal.aborted &&
            snap.statusCode >= 200 &&
            snap.statusCode < 300 &&
            scheduledScripts.size < maxScripts &&
            cleanScriptPath.includes('/src/') &&
            snap.body.length > 0
          ) {
            const imported = extractModuleImports(snap.body, cleanScriptPath, baseOrigin);
            for (const imp of imported) {
              if (scheduledScripts.size >= maxScripts) {
                break;
              }
              if (!scheduledScripts.has(imp)) {
                scheduledScripts.add(imp);
                enqueueScriptTask(imp, true);
                pump();
              }
            }
          }
        } catch (err: unknown) {
          if (budgetController.signal.aborted) {
            return;
          }
          const isTimeout =
            err instanceof Error &&
            (err.name === 'TimeoutError' || err.name === 'AbortError');
          if (!isTimeout) {
            issues.push({
              kind: 'http_error',
              severity: 'error',
              route: cleanScriptPath,
              detail: `Request failed on script ${cleanScriptPath}`,
            });
          }
        }
      });
    };

    const enqueueSubRouteTask = (routePath: string): void => {
      taskQueue.push(async () => {
        if (budgetController.signal.aborted) {
          subRouteOutcomes.set(routePath, { path: routePath, skipped: true });
          return;
        }

        try {
          const snap = await fetchSameOriginHop(
            baseOrigin,
            routePath,
            budgetController.signal,
            routeTimeoutMs,
            true,
          );

          subRouteOutcomes.set(routePath, {
            path: routePath,
            statusCode: snap.statusCode,
            contentType: snap.contentType,
            headersElapsedMs: snap.headersElapsedMs,
            truncated: snap.truncated,
          });

          if (snap.truncated) {
            issues.push({
              kind: 'truncated_body',
              severity: 'warning',
              route: routePath,
              detail: formatTruncatedBodyMessage(
                routePath,
                false,
                snap.truncatedReason,
                MAX_BODY_BYTES,
                DEFAULT_BODY_READ_TIMEOUT_MS,
              ),
            });
          }

          const isSubRouteRedirect =
            snap.statusCode >= 300 && snap.statusCode < 400;

          if (snap.statusCode >= 400) {
            const structured =
              extractNextErrorInfo(snap.body, routePath) ??
              extractViteErrorInfo(snap.body, routePath);
            if (structured) {
              issues.push({
                kind: 'http_error',
                severity: 'error',
                route: routePath,
                statusCode: snap.statusCode,
                detail: `HTTP ${snap.statusCode} on route ${routePath} (${structured.summary})`,
                maskedSnippet: structured.summary,
                ...(structured.codeFrame ? { codeFrame: structured.codeFrame } : {}),
              });
            } else {
              const masked = isHtmlLike(snap.contentType, snap.body)
                ? detectMaskedError(snap.body, routePath)
                : [];
              const snippet = masked[0]?.maskedSnippet;
              const codeFrame = masked[0]?.codeFrame;
              issues.push({
                kind: 'http_error',
                severity: 'error',
                route: routePath,
                statusCode: snap.statusCode,
                detail: snippet
                  ? `HTTP ${snap.statusCode} on route ${routePath} (${snippet})`
                  : `HTTP ${snap.statusCode} on route ${routePath}`,
                ...(snippet ? { maskedSnippet: snippet } : {}),
                ...(codeFrame ? { codeFrame } : {}),
              });
            }
          } else if (!isSubRouteRedirect && isHtmlLike(snap.contentType, snap.body)) {
            issues.push(...detectMaskedError(snap.body, routePath));
          }

          if (snap.headersElapsedMs > slowRouteMs) {
            issues.push({
              kind: 'slow_route',
              severity: 'warning',
              route: routePath,
              elapsedMs: snap.headersElapsedMs,
              detail: `slow route ${routePath} (${snap.headersElapsedMs}ms - may be dev server compilation; re-run to confirm)`,
            });
          }

          if (!isSubRouteRedirect && snap.body.length > 0) {
            issues.push(...scanSecrets(snap.body, routePath));
          }
        } catch (err: unknown) {
          if (budgetController.signal.aborted) {
            subRouteOutcomes.set(routePath, { path: routePath, skipped: true });
          } else {
            const isTimeout =
              err instanceof Error &&
              (err.name === 'TimeoutError' || err.name === 'AbortError');
            if (isTimeout) {
              subRouteOutcomes.set(routePath, {
                path: routePath,
                headersElapsedMs: routeTimeoutMs,
              });
              issues.push({
                kind: 'slow_route',
                severity: 'warning',
                route: routePath,
                elapsedMs: routeTimeoutMs,
                detail: `slow route ${routePath} (did not respond within ${routeTimeoutMs}ms - may be dev server compilation; re-run to confirm)`,
              });
            } else {
              subRouteOutcomes.set(routePath, { path: routePath });
              issues.push({
                kind: 'http_error',
                severity: 'error',
                route: routePath,
                detail: `Connection failed on route ${routePath}`,
              });
            }
          }
        }
      });
    };

    for (const scriptPath of candidateScripts) {
      enqueueScriptTask(scriptPath);
    }

    for (const routePath of subRoutes) {
      enqueueSubRouteTask(routePath);
    }

    pump();
    await poolDone;

    for (const routePath of subRoutes) {
      const item = subRouteOutcomes.get(routePath);
      if (item) {
        routes.push(item);
        if (item.skipped) {
          skippedRoutes.push(routePath);
        }
      }
    }
  } finally {
    clearTimeout(budgetTimer);
  }

  return {
    routes,
    scannedScripts,
    skippedRoutes,
    issues,
  };
}
