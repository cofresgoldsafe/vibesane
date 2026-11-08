import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  UNSAFE_HTML_SINK_RE,
  SANITIZER_HINT_RE,
  isStaticHtmlLiteral,
  UNSAFE_HTML_RULE_EXAMPLES,
} from '../dist/rules/unsafe-html.js';
import { scanUnsafeHtml } from '../dist/scanner/unsafe-html-scan.js';
import { main } from '../dist/cli.js';

function createCaptureIO() {
  let stdout = '';
  let stderr = '';
  return {
    stdout(msg) {
      stdout += String(msg) + '\n';
    },
    stderr(msg) {
      stderr += String(msg) + '\n';
    },
    getStdout() {
      return stdout;
    },
    getStderr() {
      return stderr;
    },
  };
}

function startServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      resolve({
        port,
        close: () => new Promise((res) => server.close(res)),
      });
    });
  });
}

test('UNSAFE_HTML_RULE_EXAMPLES and helper functions', () => {
  // Test shouldDetect examples
  for (const snippet of UNSAFE_HTML_RULE_EXAMPLES.shouldDetect) {
    UNSAFE_HTML_SINK_RE.lastIndex = 0;
    const match = UNSAFE_HTML_SINK_RE.exec(snippet);
    assert.ok(match, `Expected UNSAFE_HTML_SINK_RE to match: ${snippet}`);

    const sink = match[1] || match[2] || match[3] || '';
    assert.ok(sink, `Expected non-empty sink for: ${snippet}`);

    if (sink === 'innerHTML' || sink === 'outerHTML') {
      const afterEquals = snippet.slice(match.index + match[0].length);
      assert.equal(
        isStaticHtmlLiteral(afterEquals),
        false,
        `Expected isStaticHtmlLiteral to return false for: ${snippet}`,
      );
    }
  }

  // Test shouldIgnore examples
  for (const snippet of UNSAFE_HTML_RULE_EXAMPLES.shouldIgnore) {
    UNSAFE_HTML_SINK_RE.lastIndex = 0;
    const match = UNSAFE_HTML_SINK_RE.exec(snippet);
    if (match) {
      const sink = match[1] || match[2] || match[3] || '';
      if (sink === 'innerHTML' || sink === 'outerHTML') {
        const afterEquals = snippet.slice(match.index + match[0].length);
        assert.equal(
          isStaticHtmlLiteral(afterEquals),
          true,
          `Expected isStaticHtmlLiteral to return true for: ${snippet}`,
        );
      }
    }
  }
});

test('scanUnsafeHtml - Vite /src/ route with dangerouslySetInnerHTML', () => {
  const code = `
    import { jsxDEV as _jsxDEV } from "react/jsx-dev-runtime";
    export function Comp({ content }) {
      return _jsxDEV("div", {
        dangerouslySetInnerHTML: { __html: content }
      }, void 0, false);
    }
  `;

  const issues = scanUnsafeHtml(code, '/src/Comp.tsx');
  assert.equal(issues.length, 1);
  assert.equal(issues[0].kind, 'unsanitized_html');
  assert.equal(issues[0].severity, 'warning');
  assert.equal(issues[0].route, '/src/Comp.tsx');
  assert.match(issues[0].detail, /Raw HTML is injected with dangerouslySetInnerHTML in \/src\/Comp\.tsx/);
  assert.doesNotMatch(issues[0].detail, /jsxDEV/);
});

test('scanUnsafeHtml - Vite /src/ route with sanitizer hints silences', () => {
  const codeWithDompurify = `
    import DOMPurify from 'dompurify';
    export function Comp({ content }) {
      return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />;
    }
  `;
  assert.equal(scanUnsafeHtml(codeWithDompurify, '/src/Comp.tsx').length, 0);

  const codeWithSanitize = `
    function sanitize(dirty) { return dirty.replace(/<script>/gi, ''); }
    export function Comp({ content }) {
      return <div dangerouslySetInnerHTML={{ __html: sanitize(content) }} />;
    }
  `;
  assert.equal(scanUnsafeHtml(codeWithSanitize, '/src/Comp.tsx').length, 0);

  const codeWithXss = `
    import xss from 'xss';
    el.innerHTML = xss(content);
  `;
  assert.equal(scanUnsafeHtml(codeWithXss, '/src/Comp.tsx').length, 0);
});

test('scanUnsafeHtml - Webpack dev bundle user module vs third party module', () => {
  const webpackBundle = `
    /***/ "./node_modules/react-dom/cjs/react-dom.development.js":
    function setInitialDOMProperties(tag, domElement, rootContainerElement, nextProps) {
      if (propKey === 'dangerouslySetInnerHTML') {
        // internal react handling
      }
    }
    /***/
    /***/ "(app-pages-browser)/./src/app/Article.tsx":
    function Article({ body }) {
      el.innerHTML = body;
    }
    /***/
  `;

  const issues = scanUnsafeHtml(webpackBundle, '/_next/static/chunks/app.js');
  assert.equal(issues.length, 1);
  assert.equal(issues[0].route, 'src/app/Article.tsx');
  assert.equal(issues[0].kind, 'unsanitized_html');
  assert.equal(issues[0].severity, 'warning');
  assert.match(issues[0].detail, /Raw HTML is injected with innerHTML in src\/app\/Article\.tsx/);
});

test('scanUnsafeHtml - Turbopack project module', () => {
  const turbopackBundle = `
    "[project]/src/components/MarkdownView.tsx [app-client] (ecmascript)": ((__turbopack_context__) => {
      function renderMd(raw) {
        target.insertAdjacentHTML('beforeend', raw);
      }
    });
  `;

  const issues = scanUnsafeHtml(turbopackBundle, '/_next/static/chunks/turbopack.js');
  assert.equal(issues.length, 1);
  assert.equal(issues[0].route, 'src/components/MarkdownView.tsx');
  assert.equal(issues[0].kind, 'unsanitized_html');
  assert.equal(issues[0].severity, 'warning');
  assert.match(issues[0].detail, /Raw HTML is injected with insertAdjacentHTML in src\/components\/MarkdownView\.tsx/);
});

test('scanUnsafeHtml - Script without boundaries outside /src/ is ignored (zero false positives on production bundles)', () => {
  const prodBundle = `
    // minified production bundle without module boundaries
    function a(e){e.dangerouslySetInnerHTML={__html:t}}
    function b(e){e.innerHTML=t}
  `;

  const issues = scanUnsafeHtml(prodBundle, '/assets/index-D7b3.js');
  assert.equal(issues.length, 0);
});

test('scanUnsafeHtml - innerHTML and outerHTML static literals are ignored', () => {
  const script = `
    el1.innerHTML = '';
    el2.innerHTML = "";
    el3.innerHTML = \`\`;
    el4.innerHTML = '<b>ok</b>';
    el5.outerHTML = "<div>item</div>";
    eval("el6.innerHTML = \\'\\';");
    eval("el7.innerHTML = \\\"<b>escaped</b>\\\";");
  `;

  assert.equal(scanUnsafeHtml(script, '/src/StaticView.tsx').length, 0);
});

test('scanUnsafeHtml - innerHTML with template literal interpolation or concatenation triggers warning', () => {
  const script = `
    el.innerHTML = \`<div>\${userHtml}</div>\`;
  `;
  const issues = scanUnsafeHtml(script, '/src/DynamicView.tsx');
  assert.equal(issues.length, 1);
  assert.equal(issues[0].kind, 'unsanitized_html');
  assert.equal(issues[0].severity, 'warning');
});

test('scanUnsafeHtml - innerHTML comparison does not trigger', () => {
  const script = `
    if (el.innerHTML == '<p>ready</p>') {}
    if (el.innerHTML === '') {}
  `;
  assert.equal(scanUnsafeHtml(script, '/src/Check.tsx').length, 0);
});

test('scanUnsafeHtml - deduplication by (file, sink)', () => {
  const script = `
    el1.innerHTML = varA;
    el2.innerHTML = varB;
    el3.outerHTML = varC;
  `;
  const issues = scanUnsafeHtml(script, '/src/Dedupe.tsx');
  // 1 for innerHTML, 1 for outerHTML
  assert.equal(issues.length, 2);
  const sinks = issues.map((i) => i.detail);
  assert.ok(sinks.some((d) => d.includes('innerHTML')));
  assert.ok(sinks.some((d) => d.includes('outerHTML')));
});

test('scanUnsafeHtml - performance with 2MB random text + sink executes under 100ms', () => {
  const chunk = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.repeat(32000); // ~2MB
  const content = `${chunk}\n\nel.innerHTML = untrustedInput;\n${chunk}`;

  const start = performance.now();
  const issues = scanUnsafeHtml(content, '/src/Large.tsx');
  const elapsed = performance.now() - start;

  assert.equal(issues.length, 1);
  assert.ok(elapsed < 100, `Execution took ${elapsed.toFixed(2)}ms (expected < 100ms)`);
});

test('end-to-end integration: Vite app with unsanitized HTML produces warning, exit 0, no AI prompt', async () => {
  const appHtml = `<!doctype html><html><head><script type="module" src="/@vite/client"></script><script type="module" src="/src/main.tsx"></script></head><body><div id="root"></div></body></html>`;
  const scriptCode = `
    import { jsxDEV as _jsxDEV } from "react/jsx-dev-runtime";
    export function App() {
      return _jsxDEV("div", {
        dangerouslySetInnerHTML: { __html: window.userData }
      }, void 0, false);
    }
  `;

  const server = await startServer((req, res) => {
    if (req.url === '/' || req.url === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(appHtml);
      return;
    }
    if (req.url === '/@vite/client') {
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end('// vite client');
      return;
    }
    if (req.url === '/src/main.tsx') {
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end(scriptCode);
      return;
    }
    res.writeHead(404);
    res.end('Not found');
  });

  try {
    const io = createCaptureIO();
    const code = await main(['--port', String(server.port)], io);
    const stdout = io.getStdout();

    // Sendo warning, exit code DEVE ser 0
    assert.equal(code, 0, 'Exit code must be 0 for warning');
    // Deve conter a linha de warning
    assert.match(stdout, /warning \[unsanitized_html\]: Raw HTML is injected with dangerouslySetInnerHTML in \/src\/main\.tsx/);
    // NÃO deve gerar AI FIX PROMPT
    assert.doesNotMatch(stdout, /AI FIX PROMPT/);
    assert.doesNotMatch(stdout, /AI PROMPT/);
  } finally {
    await server.close();
  }
});
