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

export interface VibesaneOptions extends PortDetectorOptions, SanityScanOptions {}

export interface VibesaneResult extends PortDetectionResult {
  routes: RouteScanItem[];
  scannedScripts: string[];
  skippedRoutes: string[];
  issues: SanityIssue[];
  aiPrompt: string | null;
  message: string;
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
): string {
  const alsoSuffix =
    detection.alsoActivePorts.length > 0
      ? ` (also active: ${detection.alsoActivePorts.join(', ')})`
      : '';
  const baseLine = `vibesane: connected to ${detection.url} (${detection.elapsedMs}ms)${alsoSuffix}`;
  const coverageLine = determineCoverageLine(detection, routes, scannedScripts, warnings);

  if (ok) {
    const lines = [baseLine];
    for (const w of warnings) {
      lines.push(`warning [${w.kind}]: ${stripViteTimestampQuery(w.detail)}`);
    }
    lines.push(coverageLine);
    if (skippedRoutes.length > 0) {
      lines.push(
        `info: ${skippedRoutes.length} route(s) not checked (time budget reached): ${skippedRoutes.join(', ')}`,
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
  if (skippedRoutes.length > 0) {
    lines.push(
      `info: ${skippedRoutes.length} route(s) not checked (time budget reached): ${skippedRoutes.join(', ')}`,
    );
  }
  return lines.join('\n');
}

export async function runVibesane(options: VibesaneOptions = {}): Promise<VibesaneResult> {
  validateSanityScanOptions(options);
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
  };
}
