export const UNSAFE_HTML_SINK_RE =
  /(?:(dangerouslySetInnerHTML)|\.(innerHTML|outerHTML)\s*=(?!=)|\.(insertAdjacentHTML)\s*\()/g;

export const SANITIZER_HINT_RE = /dompurify|sanitize|purify|\bxss\b/i;

export function isStaticHtmlLiteral(textAfterEquals: string): boolean {
  if (!textAfterEquals) {
    return false;
  }
  let trimmed = textAfterEquals.trimStart();
  if (trimmed.startsWith('(')) {
    trimmed = trimmed.slice(1).trimStart();
  }

  const quoteMatch = /^(?:(\\)?"|(\\)?'|(\\)?`)/.exec(trimmed);
  if (!quoteMatch) {
    return false;
  }

  const hasBackslash = Boolean(quoteMatch[1] || quoteMatch[2] || quoteMatch[3]);
  const quoteChar = trimmed[hasBackslash ? 1 : 0]!;
  const openQuote = hasBackslash ? `\\${quoteChar}` : quoteChar;

  let closedIndex = -1;
  let i = openQuote.length;

  while (i < trimmed.length) {
    if (trimmed[i] === '\\') {
      if (hasBackslash && trimmed.slice(i, i + openQuote.length) === openQuote) {
        closedIndex = i + openQuote.length;
        break;
      }
      i += 2;
      continue;
    }
    if (!hasBackslash && trimmed[i] === quoteChar) {
      closedIndex = i + 1;
      break;
    }
    i += 1;
  }

  if (closedIndex === -1) {
    return false;
  }

  const insideString = trimmed.slice(openQuote.length, closedIndex - openQuote.length);
  if (quoteChar === '`' && insideString.includes('${')) {
    return false;
  }

  const rest = trimmed.slice(closedIndex).trimStart();
  if (rest.length === 0) {
    return true;
  }
  const nextChar = rest[0]!;
  return (
    nextChar === ';' ||
    nextChar === ',' ||
    nextChar === ')' ||
    nextChar === '}' ||
    nextChar === '\n' ||
    nextChar === '\r'
  );
}

export const UNSAFE_HTML_RULE_EXAMPLES = {
  shouldDetect: [
    'dangerouslySetInnerHTML={{ __html: userHtml }}',
    'element.innerHTML = untrustedInput;',
    'element.outerHTML = dirtyHtml;',
    'target.insertAdjacentHTML("beforeend", dynamicMarkup);',
    'element.innerHTML = `<div>${userPayload}</div>`;',
    'element.innerHTML = "<b>" + userContent;',
  ],
  shouldIgnore: [
    "element.innerHTML = '';",
    'element.innerHTML = "";',
    'element.innerHTML = ``;',
    "element.innerHTML = '<b>safe static string</b>';",
    'element.innerHTML = "<div>safe static string</div>";',
    'element.innerHTML = `<span>safe static template</span>`;',
    "element.innerHTML = \\'\\';",
    'element.innerHTML = \\"\\";',
    "element.innerHTML = \\'<b>eval static</b>\\';",
    'element.innerHTML = \\"<b>eval static</b>\\";',
    "if (element.innerHTML == '') {}",
    "if (element.innerHTML === '') {}",
    "if (element.outerHTML === '') {}",
  ],
} as const;
