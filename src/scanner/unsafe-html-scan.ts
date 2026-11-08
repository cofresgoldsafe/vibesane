import {
  extractModuleBoundaries,
  findModuleBoundaryIndex,
  type SanityIssue,
} from './security-scan.js';
import {
  UNSAFE_HTML_SINK_RE,
  SANITIZER_HINT_RE,
  isStaticHtmlLiteral,
} from '../rules/unsafe-html.js';

export function scanUnsafeHtml(content: string, route: string): SanityIssue[] {
  if (!content) {
    return [];
  }

  const issues: SanityIssue[] = [];
  const seen = new Set<string>();
  const boundaries = extractModuleBoundaries(content);

  UNSAFE_HTML_SINK_RE.lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = UNSAFE_HTML_SINK_RE.exec(content)) !== null) {
    const sink = match[1] || match[2] || match[3] || '';
    if (!sink) {
      continue;
    }

    let file: string;
    let moduleText: string;

    if (boundaries.length > 0) {
      const idx = findModuleBoundaryIndex(boundaries, match.index);
      if (idx < 0) {
        continue;
      }
      const boundary = boundaries[idx]!;
      if (boundary.isThirdParty) {
        continue;
      }
      file = boundary.path;
      const moduleStart = boundary.index;
      const moduleEnd =
        idx + 1 < boundaries.length ? boundaries[idx + 1]!.index : content.length;
      moduleText = content.slice(moduleStart, moduleEnd);
    } else {
      if (!route.startsWith('/src/')) {
        continue;
      }
      file = route;
      moduleText = content;
    }

    if (SANITIZER_HINT_RE.test(moduleText)) {
      continue;
    }

    if (sink === 'innerHTML' || sink === 'outerHTML') {
      const textAfterEquals = content.slice(match.index + match[0].length);
      if (isStaticHtmlLiteral(textAfterEquals)) {
        continue;
      }
    }

    const dedupeKey = `${file}::${sink}`;
    if (seen.has(dedupeKey)) {
      continue;
    }
    seen.add(dedupeKey);

    issues.push({
      kind: 'unsanitized_html',
      severity: 'warning',
      route: file,
      detail: `Raw HTML is injected with ${sink} in ${file} and no sanitizer (e.g. DOMPurify) appears in that file; if this HTML can come from users, an API or an LLM, it is an XSS risk`,
    });
  }

  return issues;
}
