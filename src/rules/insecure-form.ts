import { toAsciiSafe } from '../text/ascii.js';
import type { SanityIssue } from '../scanner/security-scan.js';

export const HTML_COMMENT_RE = /<!--[\s\S]*?(?:-->|$)/g;
export const SCRIPT_TAG_RE = /<script\b[^>]*>[\s\S]*?(?:<\/script\s*>|$)/gi;
export const FORM_TAG_OPEN_RE = /<form\b([^>]*)>/gi;
export const METHOD_GET_RE =
  /(?:^|\s)method\s*=\s*(?:"get"|'get'|get(?=[\s\/>]|$))/i;
export const INPUT_TAG_RE = /<input\b([^>]*)>/gi;
export const TYPE_PASSWORD_RE =
  /(?:^|\s)type\s*=\s*(?:"password"|'password'|password(?=[\s\/>]|$))/i;
export const FORM_SCOPE_END_RE = /<\/form\s*>|<form\b/gi;
export const MAX_FORM_SNIPPET_LEN = 160;

export function detectInsecureFormMethod(
  html: string,
  route: string,
): SanityIssue[] {
  if (!html) {
    return [];
  }

  const lastGt = html.lastIndexOf('>');
  if (lastGt === -1) {
    return [];
  }
  const safeHtml = html.slice(0, lastGt + 1);

  const sanitizedHtml = safeHtml
    .replace(HTML_COMMENT_RE, '')
    .replace(SCRIPT_TAG_RE, '');

  const issues: SanityIssue[] = [];
  FORM_TAG_OPEN_RE.lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = FORM_TAG_OPEN_RE.exec(sanitizedHtml)) !== null) {
    const formAttrs = match[1] ?? '';
    if (!METHOD_GET_RE.test(formAttrs)) {
      continue;
    }

    const formOpenTag = match[0];
    const formContentStart = match.index + formOpenTag.length;
    FORM_SCOPE_END_RE.lastIndex = formContentStart;
    const endMatch = FORM_SCOPE_END_RE.exec(sanitizedHtml);
    const formEnd = endMatch ? endMatch.index : sanitizedHtml.length;
    const formBody = sanitizedHtml.slice(formContentStart, formEnd);

    INPUT_TAG_RE.lastIndex = 0;
    let inputMatch: RegExpExecArray | null;
    let hasPassword = false;

    while ((inputMatch = INPUT_TAG_RE.exec(formBody)) !== null) {
      const inputAttrs = inputMatch[1] ?? '';
      if (TYPE_PASSWORD_RE.test(inputAttrs)) {
        hasPassword = true;
        break;
      }
    }

    if (!hasPassword) {
      continue;
    }

    let snippet = toAsciiSafe(formOpenTag.trim());
    if (snippet.length > MAX_FORM_SNIPPET_LEN) {
      snippet = snippet.slice(0, MAX_FORM_SNIPPET_LEN - 3) + '...';
    }

    issues.push({
      kind: 'insecure_form_method',
      severity: 'error',
      route,
      detail: `form on ${route} sends a password field with method=get; use method=post so the password does not end up in the URL, history and server logs`,
      maskedSnippet: snippet,
    });
  }

  return issues;
}
