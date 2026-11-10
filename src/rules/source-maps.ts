import type { SanityIssue } from '../scanner/security-scan.js';

const SOURCEMAP_COMMENT_RE = /(?:\/\/[#@]\s*sourceMappingURL=([^\s'"]+))(?:\s*$)/m;

export function extractSourceMapComment(jsBody: string): string | null {
  if (!jsBody || jsBody.length === 0) {
    return null;
  }
  const match = SOURCEMAP_COMMENT_RE.exec(jsBody);
  return match ? match[1] ?? null : null;
}

export function deriveSourceMapUrl(scriptUrl: string): string {
  const cleanUrl = scriptUrl.split('?')[0]!;
  return `${cleanUrl}.map`;
}

export function resolveSourceMapTarget(
  commentMap: string | null,
  scriptPath: string,
  baseOrigin: string,
): string | null {
  if (commentMap) {
    const trimmed = commentMap.trim();
    if (trimmed.toLowerCase().startsWith('data:')) {
      return null;
    }
    try {
      const resolved = new URL(trimmed, new URL(scriptPath, baseOrigin));
      const baseObj = new URL(baseOrigin);
      if (resolved.origin !== baseObj.origin) {
        return null;
      }
      return `${resolved.pathname}${resolved.search}`;
    } catch {
      return null;
    }
  }
  return deriveSourceMapUrl(scriptPath);
}

export function isLegitimateSourceMap(body: string, contentType?: string): boolean {
  if (!body) {
    return false;
  }

  const trimmed = body.trimStart();
  // Se começar com < (ou Content-Type text/html), é fallback HTML de SPA
  if (trimmed.startsWith('<')) {
    return false;
  }
  if (contentType && contentType.toLowerCase().includes('text/html')) {
    return false;
  }

  try {
    const parsed = JSON.parse(body) as {
      version?: unknown;
      sources?: unknown;
    };
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      'version' in parsed &&
      Array.isArray(parsed.sources) &&
      parsed.sources.length > 0
    ) {
      return true;
    }
  } catch {
    // Não é JSON válido
  }

  return false;
}

export function createExposedSourceMapIssue(mapRoute: string): SanityIssue {
  return {
    kind: 'exposed_source_map',
    severity: 'warning',
    route: mapRoute,
    detail: `Production source map is publicly accessible at ${mapRoute} (exposes original unminified source code)`,
  };
}
