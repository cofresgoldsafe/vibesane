import {
  DEFAULT_PORTS,
  DEFAULT_TCP_TIMEOUT_MS,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_BODY_READ_TIMEOUT_MS,
  DEFAULT_SCRIPT_BODY_READ_TIMEOUT_MS,
  MAX_BODY_BYTES,
  MAX_SCRIPT_BODY_BYTES,
  assertValidPort,
  assertValidTimeout,
  readBoundedTextBody,
  probeTcpPort,
  detectServer,
  type LoopbackHost,
  type DetectionFailureReason,
  type TruncatedReason,
  type PortDetectorOptions,
  type TcpProbeResult,
  type RootHttpSnapshot,
  type PortDetectionResult,
} from './scanner/port-detector.js';
import {
  redactSecret,
  redactPassword,
  redactConnectionUri,
  stripViteTimestampQuery,
  resolveBundledSourceFile,
  sanitizeSecretsInText,
  sanitizeErrorSnippet,
  extractViteErrorInfo,
  extractNextErrorInfo,
  detectMaskedError,
  scanSecrets,
  type SanitySeverity,
  type SanityIssueKind,
  type SanityIssue,
} from './scanner/security-scan.js';
import {
  DEFAULT_SCAN_BUDGET_MS,
  DEFAULT_ROUTE_TIMEOUT_MS,
  DEFAULT_SLOW_ROUTE_MS,
  DEFAULT_MAX_ROUTES,
  DEFAULT_MAX_SCRIPTS,
  DEFAULT_MAX_CONCURRENCY,
  MAX_REDIRECTS,
  isExcludedFrameworkScript,
  getScriptPriority,
  extractInternalLinks,
  extractCandidateScripts,
  selectScriptsToFetch,
  extractModuleImports,
  formatTruncatedBodyMessage,
  isSameLocalOrigin,
  runSanityScan,
  type RouteScanItem,
  type SanityScanOptions,
  type InternalRouteScanOptions,
  type SanityScanSummary,
} from './scanner/route-crawler.js';
import {
  AI_PROMPT_HEADER,
  SECRET_LEAK_INSTRUCTION,
  CODE_ERROR_INSTRUCTION,
  MAX_PROMPT_ERRORS,
  stripAnsiCodes,
  generateAiFixPrompt,
  type AiPromptIssue,
  type AiPromptInput,
} from './reporter/ai-prompt-gen.js';
import {
  shouldEnableColor,
  formatTerminalReport,
  type VibesaneReportInput,
  type TerminalReportOptions,
} from './reporter/terminal-ui.js';
import { initRemoteTarget } from './scanner/remote-init.js';

export type AiPromptIssueInput = AiPromptIssue;

export {
  DEFAULT_PORTS,
  DEFAULT_TCP_TIMEOUT_MS,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_BODY_READ_TIMEOUT_MS,
  DEFAULT_SCRIPT_BODY_READ_TIMEOUT_MS,
  MAX_BODY_BYTES,
  MAX_SCRIPT_BODY_BYTES,
  assertValidPort,
  assertValidTimeout,
  readBoundedTextBody,
  probeTcpPort,
  detectServer,
  type LoopbackHost,
  type DetectionFailureReason,
  type TruncatedReason,
  type PortDetectorOptions,
  type TcpProbeResult,
  type RootHttpSnapshot,
  type PortDetectionResult,
  redactSecret,
  redactPassword,
  redactConnectionUri,
  stripViteTimestampQuery,
  resolveBundledSourceFile,
  sanitizeSecretsInText,
  sanitizeErrorSnippet,
  extractViteErrorInfo,
  extractNextErrorInfo,
  detectMaskedError,
  scanSecrets,
  type SanitySeverity,
  type SanityIssueKind,
  type SanityIssue,
  DEFAULT_SCAN_BUDGET_MS,
  DEFAULT_ROUTE_TIMEOUT_MS,
  DEFAULT_SLOW_ROUTE_MS,
  DEFAULT_MAX_ROUTES,
  DEFAULT_MAX_SCRIPTS,
  DEFAULT_MAX_CONCURRENCY,
  MAX_REDIRECTS,
  isExcludedFrameworkScript,
  getScriptPriority,
  extractInternalLinks,
  extractCandidateScripts,
  selectScriptsToFetch,
  extractModuleImports,
  formatTruncatedBodyMessage,
  runSanityScan,
  type RouteScanItem,
  type SanityScanOptions,
  type SanityScanSummary,
  AI_PROMPT_HEADER,
  SECRET_LEAK_INSTRUCTION,
  CODE_ERROR_INSTRUCTION,
  MAX_PROMPT_ERRORS,
  stripAnsiCodes,
  generateAiFixPrompt,
  type AiPromptIssue,
  type AiPromptInput,
  shouldEnableColor,
  formatTerminalReport,
  type VibesaneReportInput,
  type TerminalReportOptions,
};

export const EXIT_CODES = {
  OK: 0,
  SANITY_FAILURE: 1,
  USAGE_ERROR: 2,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

export interface VibesaneOptions extends PortDetectorOptions, SanityScanOptions {
  url?: string;
}

export interface VibesaneResult extends PortDetectionResult {
  routes: RouteScanItem[];
  scannedScripts: string[];
  skippedRoutes: string[];
  issues: SanityIssue[];
  aiPrompt: string | null;
  message: string;
  probedApiRoutes: string[];
  uncompletedSecurityProbes?: { count: number; reason: string }[];
  skipReason?: 'request limit reached' | 'time budget reached';
}

function validateSanityScanOptions(options: SanityScanOptions): void {
  if (options.scanBudgetMs !== undefined) {
    assertValidTimeout(options.scanBudgetMs, 'scanBudgetMs');
  }
  if (options.routeTimeoutMs !== undefined) {
    assertValidTimeout(options.routeTimeoutMs, 'routeTimeoutMs');
  }
  if (options.slowRouteMs !== undefined) {
    assertValidTimeout(options.slowRouteMs, 'slowRouteMs');
  }
  if (
    options.maxRoutes !== undefined &&
    (!Number.isInteger(options.maxRoutes) || options.maxRoutes < 1)
  ) {
    throw new RangeError(`Invalid maxRoutes "${options.maxRoutes}": expected integer >= 1`);
  }
  if (
    options.maxScripts !== undefined &&
    (!Number.isInteger(options.maxScripts) || options.maxScripts < 0)
  ) {
    throw new RangeError(`Invalid maxScripts "${options.maxScripts}": expected integer >= 0`);
  }
  if (
    options.maxConcurrency !== undefined &&
    (!Number.isInteger(options.maxConcurrency) || options.maxConcurrency < 1)
  ) {
    throw new RangeError(
      `Invalid maxConcurrency "${options.maxConcurrency}": expected integer >= 1`,
    );
  }
}

function determineCoverageLine(
  detection: PortDetectionResult,
  routes: readonly RouteScanItem[],
  scannedScripts: readonly string[],
  warnings: readonly SanityIssue[],
): string {
  const candidateRoutes = routes.filter((r) => {
    if (r.skipped || r.statusCode === undefined) {
      return false;
    }
    if (r.statusCode >= 300 && r.statusCode < 400) {
      return false;
    }
    return true;
  });

  let checkedPagesCount = 0;
  let checkedJsonCount = 0;

  for (const r of candidateRoutes) {
    const isJson =
      typeof r.contentType === 'string' &&
      r.contentType.toLowerCase().includes('json');
    if (isJson) {
      checkedJsonCount++;
    } else {
      checkedPagesCount++;
    }
  }

  const checkedScriptsCount = scannedScripts.length;

  if (checkedPagesCount === 0 && checkedJsonCount === 0) {
    const hasRootSlowRoute = warnings.some(
      (w) => w.kind === 'slow_route' && w.route === '/',
    );
    if (hasRootSlowRoute) {
      return 'info: nothing was checked (/ did not respond in time); re-run after the dev server finishes compiling';
    }

    if (
      detection.url &&
      detection.rootResponse &&
      detection.rootResponse.statusCode >= 300 &&
      detection.rootResponse.statusCode < 400 &&
      typeof detection.rootResponse.location === 'string'
    ) {
      try {
        const base = new URL(detection.url);
        const target = new URL(detection.rootResponse.location, base);
        if (!isSameLocalOrigin(target, base)) {
          return 'info: nothing was checked (/ redirects outside the local server)';
        }
      } catch {
        // Fallback silently if URL parsing fails
      }
    }

    return 'info: nothing was checked';
  }

  const pageLabel = checkedPagesCount === 1 ? '1 page' : `${checkedPagesCount} pages`;
  const scriptLabel = checkedScriptsCount === 1 ? '1 script' : `${checkedScriptsCount} scripts`;
  const jsonLabel =
    checkedJsonCount === 1 ? '1 JSON response' : `${checkedJsonCount} JSON responses`;

  if (checkedPagesCount === 0) {
    return `info: checked ${jsonLabel} (API-only server: only HTTP status and secrets in the response were checked)`;
  }

  if (checkedJsonCount === 0) {
    return `info: checked ${pageLabel}, ${scriptLabel}`;
  }

  return `info: checked ${pageLabel}, ${scriptLabel}, ${jsonLabel}`;
}

function formatScanMessage(
  detection: PortDetectionResult,
  ok: boolean,
  errors: readonly SanityIssue[],
  warnings: readonly SanityIssue[],
  skippedRoutes: readonly string[],
  routes: readonly RouteScanItem[],
  scannedScripts: readonly string[],
  probedApiRoutes: readonly string[] = [],
  redirectedFrom?: string,
  isRemote = false,
  skipReason?: 'request limit reached' | 'time budget reached',
  uncompletedSecurityProbes?: { count: number; reason: string }[],
): string {
  const alsoSuffix =
    detection.alsoActivePorts.length > 0
      ? ` (also active: ${detection.alsoActivePorts.join(', ')})`
      : '';
  const baseLine = redirectedFrom
    ? `vibesane: scanning ${detection.url} (redirected from ${redirectedFrom})`
    : `vibesane: connected to ${detection.url} (${detection.elapsedMs}ms)${alsoSuffix}`;
  const coverageLine = determineCoverageLine(detection, routes, scannedScripts, warnings);
  const probedLine =
    probedApiRoutes.length > 0
      ? `info: probed ${probedApiRoutes.length === 1 ? '1 GET route' : `${probedApiRoutes.length} GET routes`} listed in /openapi.json`
      : null;

  const skippedLimitLabel =
    skipReason ?? (isRemote ? 'request limit reached' : 'time budget reached');

  if (ok) {
    const lines = [baseLine];
    for (const w of warnings) {
      lines.push(`warning [${w.kind}]: ${stripViteTimestampQuery(w.detail)}`);
    }
    lines.push(coverageLine);
    if (probedLine) {
      lines.push(probedLine);
    }
    if (uncompletedSecurityProbes && uncompletedSecurityProbes.length > 0) {
      for (const p of uncompletedSecurityProbes) {
        lines.push(`info: ${p.count} security probe(s) not completed (${p.reason})`);
      }
    }
    if (skippedRoutes.length > 0) {
      lines.push(
        `info: ${skippedRoutes.length} route(s) not checked (${skippedLimitLabel}): ${skippedRoutes.join(', ')}`,
      );
    }
    return lines.join('\n');
  }

  const lines = [
    `vibesane: sanity check failed on ${detection.url} (${errors.length} error(s))`,
  ];
  for (const e of errors) {
    const cleanDetail = stripViteTimestampQuery(e.detail);
    lines.push(`error [${e.kind}]: ${cleanDetail}`);
  }
  for (const w of warnings) {
    lines.push(`warning [${w.kind}]: ${stripViteTimestampQuery(w.detail)}`);
  }
  lines.push(coverageLine);
  if (probedLine) {
    lines.push(probedLine);
  }
  if (uncompletedSecurityProbes && uncompletedSecurityProbes.length > 0) {
    for (const p of uncompletedSecurityProbes) {
      lines.push(`info: ${p.count} security probe(s) not completed (${p.reason})`);
    }
  }
  if (skippedRoutes.length > 0) {
    lines.push(
      `info: ${skippedRoutes.length} route(s) not checked (${skippedLimitLabel}): ${skippedRoutes.join(', ')}`,
    );
  }
  return lines.join('\n');
}

export async function runVibesane(options: VibesaneOptions = {}): Promise<VibesaneResult> {
  validateSanityScanOptions(options);

  if (options.url !== undefined) {
    const rawTarget = options.url.trim();
    const parsed = new URL(rawTarget);
    const targetPort = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);

    const init = await initRemoteTarget(rawTarget, { routeTimeoutMs: options.routeTimeoutMs });
    if (!init.ok) {
      if (init.tlsError) {
        const issue: SanityIssue = {
          kind: 'insecure_transport',
          severity: 'error',
          route: '/',
          detail: `TLS connection failed: certificate verification failed (${init.tlsError})`,
        };
        const message = `vibesane: sanity check failed on ${rawTarget} (1 error(s))\nerror [insecure_transport]: ${issue.detail}\ninfo: nothing was checked`;
        const aiPrompt = generateAiFixPrompt({
          ok: false,
          port: targetPort,
          url: rawTarget,
          issues: [issue],
        });
        return {
          ok: false,
          port: targetPort,
          url: rawTarget,
          statusCode: undefined,
          elapsedMs: 0,
          alsoActivePorts: [],
          checkedPorts: [],
          routes: [],
          scannedScripts: [],
          skippedRoutes: [],
          issues: [issue],
          aiPrompt,
          message,
          probedApiRoutes: [],
        };
      }

      // Falha de rede não-TLS (ENOTFOUND, ECONNREFUSED, ETIMEDOUT, EAI_AGAIN, etc.)
      const failReason = init.unreachableCode ?? 'connection failed';
      const message = `vibesane: could not reach ${rawTarget} (${failReason})`;
      return {
        ok: false,
        port: null,
        url: rawTarget,
        statusCode: undefined,
        elapsedMs: 0,
        alsoActivePorts: [],
        checkedPorts: [],
        routes: [],
        scannedScripts: [],
        skippedRoutes: [],
        issues: [],
        aiPrompt: null,
        message,
        probedApiRoutes: [],
      };
    }

    const finalPort = parsed.port
      ? Number(parsed.port)
      : (new URL(init.finalUrl).protocol === 'https:' ? 443 : 80);

    const detection: PortDetectionResult = {
      ok: true,
      port: finalPort,
      url: init.finalUrl,
      elapsedMs: init.rootResponse?.headersElapsedMs ?? 0,
      alsoActivePorts: [],
      checkedPorts: [],
      rootResponse: init.rootResponse,
    };

    const scan = await runSanityScan(
      new URL(init.baseOrigin).hostname,
      finalPort,
      init.rootResponse!,
      {
        ...options,
        baseOrigin: init.baseOrigin,
        isRemote: true,
        initialRequestCount: init.requestCount,
        rootHeaders: init.rawHeaders,
      },
    );

    const normalizedIssues = scan.issues.map((issue) => ({
      ...issue,
      route: stripViteTimestampQuery(issue.route),
    }));

    const errors = normalizedIssues.filter((i) => i.severity === 'error');
    const warnings = normalizedIssues.filter((i) => i.severity === 'warning');
    const ok = errors.length === 0;

    const message = formatScanMessage(
      detection,
      ok,
      errors,
      warnings,
      scan.skippedRoutes,
      scan.routes,
      scan.scannedScripts,
      scan.probedApiRoutes,
      init.redirectedFrom,
      true,
      scan.skipReason,
      scan.uncompletedSecurityProbes,
    );

    const aiPrompt = generateAiFixPrompt({
      ok,
      port: detection.port,
      url: detection.url,
      issues: normalizedIssues,
    });

    return {
      ...detection,
      ok,
      routes: scan.routes,
      scannedScripts: scan.scannedScripts,
      skippedRoutes: scan.skippedRoutes,
      issues: normalizedIssues,
      aiPrompt,
      message,
      probedApiRoutes: scan.probedApiRoutes,
      uncompletedSecurityProbes: scan.uncompletedSecurityProbes,
      skipReason: scan.skipReason,
    };
  }

  const detection = await detectServer(options);

  if (!detection.ok || detection.port === null || !detection.host || !detection.rootResponse) {
    let message: string;
    if (detection.reason === 'http_timeout') {
      const httpTimeoutMs = options.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
      const label = httpTimeoutMs % 1000 === 0 ? `${httpTimeoutMs / 1000}s` : `${httpTimeoutMs}ms`;
      message = `vibesane: port ${detection.port} accepted the connection but took >${label} to respond (still compiling?)`;
    } else if (detection.reason === 'non_http') {
      message = `vibesane: port ${detection.port} is open but did not respond to HTTP`;
    } else {
      if (detection.checkedPorts.length === 1) {
        message = `vibesane: no active server found on port ${detection.checkedPorts[0]}`;
      } else {
        message = `vibesane: no active server found on ports ${detection.checkedPorts.join(', ')}`;
      }
    }

    return {
      ...detection,
      routes: [],
      scannedScripts: [],
      skippedRoutes: [],
      issues: [],
      aiPrompt: null,
      message,
      probedApiRoutes: [],
    };
  }

  const scan = await runSanityScan(
    detection.host,
    detection.port,
    detection.rootResponse,
    options,
  );

  const normalizedIssues = scan.issues.map((issue) => ({
    ...issue,
    route: stripViteTimestampQuery(issue.route),
  }));

  const errors = normalizedIssues.filter((i) => i.severity === 'error');
  const warnings = normalizedIssues.filter((i) => i.severity === 'warning');
  const ok = errors.length === 0;

  const message = formatScanMessage(
    detection,
    ok,
    errors,
    warnings,
    scan.skippedRoutes,
    scan.routes,
    scan.scannedScripts,
    scan.probedApiRoutes,
    undefined,
    false,
    scan.skipReason,
    scan.uncompletedSecurityProbes,
  );
  const aiPrompt = generateAiFixPrompt({
    ok,
    port: detection.port,
    url: detection.url,
    issues: normalizedIssues,
  });

  return {
    ...detection,
    ok,
    routes: scan.routes,
    scannedScripts: scan.scannedScripts,
    skippedRoutes: scan.skippedRoutes,
    issues: normalizedIssues,
    aiPrompt,
    message,
    probedApiRoutes: scan.probedApiRoutes,
    uncompletedSecurityProbes: scan.uncompletedSecurityProbes,
    skipReason: scan.skipReason,
  };
}
