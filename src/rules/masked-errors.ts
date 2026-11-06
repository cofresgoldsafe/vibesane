export interface MaskedErrorRule {
  readonly id: string;
  readonly label: string;
  readonly matches: (html: string) => boolean;
  readonly examples: {
    readonly shouldDetect: readonly string[];
    readonly shouldIgnore: readonly string[];
  };
}

const NEXT_DATA_SCRIPT_RE = /<script\b[^>]*\bid=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/gi;
const TITLE_500_RE = /<title\b[^>]*>\s*(?:500(?:\b|\s|:|-)|Internal Server Error\b)/i;
const H1_500_RE = /<h1\b[^>]*>\s*(?:500(?:\b|\s|:|-)|Internal Server Error\b)/i;

export function hasNextDataError(html: string): boolean {
  NEXT_DATA_SCRIPT_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  let foundClosedTag = false;
  while ((match = NEXT_DATA_SCRIPT_RE.exec(html)) !== null) {
    foundClosedTag = true;
    const body = match[1] ?? '';
    if (
      /"err"\s*:\s*\{\s*"name"\s*:/.test(body) ||
      /"statusCode"\s*:\s*500\b/.test(body)
    ) {
      return true;
    }
  }

  if (foundClosedTag) {
    return false;
  }

  const nextDataIdx = html.indexOf('<script id="__NEXT_DATA__"');
  if (nextDataIdx !== -1) {
    const truncatedTail = html.slice(nextDataIdx);
    if (
      /"err"\s*:\s*\{\s*"name"\s*:/.test(truncatedTail) ||
      /"statusCode"\s*:\s*500\b/.test(truncatedTail)
    ) {
      return true;
    }
  }

  return false;
}

export function hasNextErrorContext(html: string): boolean {
  if (/id=["']__next_error__["']/.test(html)) {
    return true;
  }
  if (
    html.includes('__next_error__') &&
    (html.includes('Server Error') || html.includes('Unhandled Runtime Error'))
  ) {
    return true;
  }
  return false;
}

export const MASKED_ERROR_RULES: readonly MaskedErrorRule[] = [
  {
    id: 'nextjs-container-errors',
    label: 'nextjs__container_errors',
    matches: (html) => html.includes('nextjs__container_errors'),
    examples: {
      shouldDetect: ['<div id="nextjs__container_errors">Error</div>'],
      shouldIgnore: ['<div id="app">Loaded OK</div>'],
    },
  },
  {
    id: 'unhandled-runtime-error',
    label: 'Unhandled Runtime Error',
    matches: (html) => html.includes('Unhandled Runtime Error'),
    examples: {
      shouldDetect: ['<div>Unhandled Runtime Error</div>'],
      shouldIgnore: ['<div>Runtime initialized</div>'],
    },
  },
  {
    id: 'client-side-exception',
    label: 'Application error: a client-side exception has occurred',
    matches: (html) => html.includes('Application error: a client-side exception has occurred'),
    examples: {
      shouldDetect: ['<h2>Application error: a client-side exception has occurred</h2>'],
      shouldIgnore: ['<h2>Application loaded</h2>'],
    },
  },
  {
    id: 'next-error-context',
    label: '__next_error__',
    matches: (html) => hasNextErrorContext(html),
    examples: {
      shouldDetect: ['<html id="__next_error__"><body></body></html>'],
      shouldIgnore: ['<script>window.__next_error__ = false;</script>'],
    },
  },
  {
    id: 'nextjs-portal',
    label: '<nextjs-portal',
    matches: (html) => html.includes('<nextjs-portal'),
    examples: {
      shouldDetect: ['<nextjs-portal></nextjs-portal>'],
      shouldIgnore: ['<div class="portal"></div>'],
    },
  },
  {
    id: 'next-data-error-payload',
    label: '__NEXT_DATA__ error payload',
    matches: (html) => hasNextDataError(html),
    examples: {
      shouldDetect: [
        '<script id="__NEXT_DATA__" type="application/json">{"props":{},"page":"/_error","statusCode":500}</script>',
      ],
      shouldIgnore: [
        '<script id="__NEXT_DATA__" type="application/json">{"props":{},"page":"/","statusCode":200}</script>',
      ],
    },
  },
  {
    id: 'vite-error-overlay',
    label: 'vite-error-overlay',
    matches: (html) => html.includes('<vite-error-overlay') || html.includes('vite-error-overlay'),
    examples: {
      shouldDetect: ['<vite-error-overlay></vite-error-overlay>'],
      shouldIgnore: ['<div class="vite-app"></div>'],
    },
  },
  {
    id: 'vite-plugin-error',
    label: '[plugin:vite:',
    matches: (html) => html.includes('[plugin:vite:'),
    examples: {
      shouldDetect: ['<pre>[plugin:vite:</pre>'],
      shouldIgnore: ['<pre>[plugin:custom]</pre>'],
    },
  },
  {
    id: 'vite-pre-transform-error',
    label: 'Pre-transform error:',
    matches: (html) => html.includes('Pre-transform error:'),
    examples: {
      shouldDetect: ['<pre>Pre-transform error:</pre>'],
      shouldIgnore: ['<pre>Transform complete</pre>'],
    },
  },
  {
    id: 'html-500-heading',
    label: 'HTML 500 / Internal Server Error heading',
    matches: (html) => TITLE_500_RE.test(html) || H1_500_RE.test(html),
    examples: {
      shouldDetect: [
        '<html><head><title>500 Internal Server Error</title></head><body><h1>Internal Server Error</h1></body></html>',
      ],
      shouldIgnore: [
        '<html><head><title>200 OK</title></head><body><h1>5000 items sold</h1></body></html>',
      ],
    },
  },
];
