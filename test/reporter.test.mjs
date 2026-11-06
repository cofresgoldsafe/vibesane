import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createServer } from 'node:http';
import { main } from '../dist/cli.js';
import { toAsciiSafe } from '../dist/text/ascii.js';
import { detailContainsRoute } from '../dist/reporter/ai-prompt-gen.js';
import {
  runVibesane,
  EXIT_CODES,
  AI_PROMPT_HEADER,
  SECRET_LEAK_INSTRUCTION,
  CODE_ERROR_INSTRUCTION,
  redactPassword,
  redactConnectionUri,
  stripViteTimestampQuery,
  resolveBundledSourceFile,
  extractViteErrorInfo,
  extractNextErrorInfo,
  scanSecrets,
  generateAiFixPrompt,
  formatTerminalReport,
  shouldEnableColor,
} from '../dist/index.js';

/**
 * Starts an ephemeral HTTP server on 127.0.0.1.
 * @param {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void} handler
 * @returns {Promise<{ server: import('node:http').Server, port: number, close: () => Promise<void> }>}
 */
function startHttpServer(handler) {
  return new Promise((resolve, reject) => {
    const server = createServer(handler);
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      resolve({
        server,
        port,
        close: () =>
          new Promise((resClose) => {
            server.closeAllConnections?.();
            server.close(() => resClose());
          }),
      });
    });
  });
}

/**
 * Helper to execute main() capturing stdout and stderr in memory.
 * @param {string[]} argv
 */
async function runCli(argv) {
  const out = [];
  const err = [];
  const code = await main(argv, {
    stdout: (m) => out.push(m),
    stderr: (m) => err.push(m),
  });
  return {
    code,
    stdout: out.join('\n'),
    stderr: err.join('\n'),
  };
}

describe('AI Fix Formatter & Terminal UI Reporter (BDD)', () => {
  it('1. Cabeçalho e Idioma em Inglês + stdout no CLI (vibesane | clip) com instruções de secret_leak e erro de código', async () => {
    const fakeStripeKey = ['sk', 'live', '99887766554433221100abcd'].join('_');

    const srv = await startHttpServer((req, res) => {
      const url = req.url ?? '/';
      if (url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
          <html>
            <body>
              <a href="/broken-route">Broken</a>
              <script>const leaked = "${fakeStripeKey}";</script>
            </body>
          </html>
        `);
        return;
      }
      if (url === '/broken-route') {
        res.writeHead(500, { 'Content-Type': 'text/html' });
        res.end('<html><body>Internal Crash</body></html>');
        return;
      }
      res.writeHead(404);
      res.end();
    });

    try {
      const cliRes = await runCli(['--port', String(srv.port)]);
      assert.equal(cliRes.code, EXIT_CODES.SANITY_FAILURE);
      assert.equal(cliRes.code, 1);
      assert.equal(cliRes.stderr, '');
      assert.ok(cliRes.stdout.includes(AI_PROMPT_HEADER));
      assert.ok(cliRes.stdout.includes(SECRET_LEAK_INSTRUCTION));
      assert.ok(cliRes.stdout.includes(CODE_ERROR_INSTRUCTION));

      const secretOnlyPrompt = generateAiFixPrompt({
        ok: false,
        port: srv.port,
        url: `http://localhost:${srv.port}`,
        issues: [
          {
            kind: 'secret_leak',
            severity: 'error',
            route: '/',
            detail: 'Secret leak on /: Stripe secret key (sk_live_****abcd)',
          },
        ],
      });
      assert.ok(secretOnlyPrompt);
      assert.ok(secretOnlyPrompt.includes(AI_PROMPT_HEADER));
      assert.ok(secretOnlyPrompt.includes(`Instruction: ${SECRET_LEAK_INSTRUCTION}`));
      assert.equal(secretOnlyPrompt.includes(CODE_ERROR_INSTRUCTION), false);

      const codeOnlyPrompt = generateAiFixPrompt({
        ok: false,
        port: srv.port,
        url: `http://localhost:${srv.port}`,
        issues: [
          {
            kind: 'http_error',
            severity: 'error',
            route: '/broken-route',
            detail: 'HTTP 500 on route /broken-route',
          },
        ],
      });
      assert.ok(codeOnlyPrompt);
      assert.ok(codeOnlyPrompt.includes(AI_PROMPT_HEADER));
      assert.ok(codeOnlyPrompt.includes(`Instruction: ${CODE_ERROR_INSTRUCTION}`));
      assert.equal(codeOnlyPrompt.includes(SECRET_LEAK_INSTRUCTION), false);
    } finally {
      await srv.close();
    }
  });

  it('2. Extração estruturada de erro do Vite (const error = {...} via JSON.parse, sem expor caminho absoluto loc.file, frame <= 10 linhas com segredos mascarados e remoção de ?t=)', async () => {
    const fakeKey = ['sk', 'live', '11112222333344445555abcd'].join('_');
    const longFrame = [
      `1 | const sk = "${fakeKey}";`,
      '2 | export const Pay = () => <div',
      '   |                              ^',
      '3 |   className="pay-box"',
      '4 | >',
      '5 |   <span>Checkout</span>',
      '6 | </div>;',
      '7 | // line 7',
      '8 | // line 8',
      '9 | // line 9',
      '10 | // line 10',
      '11 | // line 11 should be truncated',
      '12 | // line 12 should be truncated',
    ].join('\n');

    const viteErrorPayload = {
      message: 'C:/Users/Alexandre/project/src/components/Pay.tsx: Unexpected token (1:65)',
      loc: {
        file: 'C:/Users/Alexandre/project/src/components/Pay.tsx',
        line: 1,
        column: 65,
      },
      frame: longFrame,
    };

    const srv = await startHttpServer((req, res) => {
      const url = req.url ?? '/';
      if (url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(
          '<html><body><script type="module" src="/src/main.tsx?t=1730900000000"></script></body></html>',
        );
        return;
      }
      if (url.startsWith('/src/main.tsx')) {
        res.writeHead(200, { 'Content-Type': 'application/javascript' });
        res.end('import { Pay } from "/src/components/Pay.tsx?t=1730900000000";\nconsole.log(Pay);');
        return;
      }
      if (url.startsWith('/src/components/Pay.tsx')) {
        res.writeHead(500, { 'Content-Type': 'application/javascript' });
        res.end(
          `import { createHotContext as __vite__createHotContext } from "/@vite/client";\nconst error = ${JSON.stringify(viteErrorPayload)};\nthrow error;`,
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });

    try {
      assert.equal(
        stripViteTimestampQuery('/src/components/Pay.tsx?t=1730900000000'),
        '/src/components/Pay.tsx',
      );

      const res = await runVibesane({ port: srv.port });
      assert.equal(res.ok, false);
      assert.ok(res.aiPrompt, 'aiPrompt deve ser gerado quando ok: false');

      const report = formatTerminalReport(res, { color: false });

      // Caminho absoluto local nunca pode vazar
      assert.equal(report.includes('C:/Users/Alexandre'), false);
      assert.equal(res.aiPrompt.includes('C:/Users/Alexandre'), false);

      // Caminho servido com linha:coluna deve aparecer sem ?t=1730900000000
      assert.equal(report.includes('?t=1730900000000'), false);
      assert.equal(res.aiPrompt.includes('?t=1730900000000'), false);
      assert.ok(
        res.aiPrompt.includes('/src/components/Pay.tsx:1:65'),
        `Esperava /src/components/Pay.tsx:1:65 no prompt:\n${res.aiPrompt}`,
      );
      assert.ok(res.aiPrompt.includes('Unexpected token (1:65)'));

      // Frame deve estar presente, limitado a 10 linhas e com a chave mascarada
      const expectedMasked = ['sk', 'live', '****abcd'].join('_');
      assert.ok(res.aiPrompt.includes(expectedMasked));
      assert.equal(res.aiPrompt.includes('11112222333344445555'), false);
      assert.equal(report.includes('11112222333344445555'), false);
      assert.equal(res.aiPrompt.includes('line 11 should be truncated'), false);
    } finally {
      await srv.close();
    }
  });

  it('3. Extração estruturada de erro do Next 16 (página 500 com múltiplos pagePath: layout, __next_builtin__not-found.js e broken/page.tsx)', async () => {
    const next16Html = `
      <!DOCTYPE html>
      <html>
        <head><title>500: Internal Server Error</title></head>
        <body>
          <script>
            self.__next_f.push([1,"0:[\\"$\\",\\"html\\",null,{\\"children\\":\\"Server Error\\"}]\\n"]);
            self.__next_f.push([1,"1:{\\"type\\":\\"layout\\",\\"pagePath\\":\\"layout.tsx\\"}\\n"]);
            self.__next_f.push([1,"2:{\\"type\\":\\"not-found\\",\\"pagePath\\":\\"__next_builtin__not-found.js\\"}\\n"]);
            self.__next_f.push([1,"3:{\\"type\\":\\"error\\",\\"pagePath\\":\\"__next_builtin__global-error.js\\"}\\n"]);
            self.__next_f.push([1,"4:{\\"type\\":\\"page\\",\\"pagePath\\":\\"broken/page.tsx\\"}\\n"]);
            self.__next_f.push([1,"5:{\\"name\\":\\"TypeError\\",\\"message\\":\\"Cannot read properties of undefined (reading 'name')\\"}\\n"]);
          </script>
        </body>
      </html>
    `;

    const extracted = extractNextErrorInfo(next16Html, '/broken');
    assert.ok(extracted);
    assert.equal(
      extracted.summary,
      "broken/page.tsx - TypeError: Cannot read properties of undefined (reading 'name')",
    );
    assert.equal(extracted.summary.includes('__next_builtin__'), false);
    assert.equal(extracted.summary.includes('layout.tsx'), false);

    const srv = await startHttpServer((req, res) => {
      const url = req.url ?? '/';
      if (url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body><a href="/broken">Broken Next Route</a></body></html>');
        return;
      }
      if (url === '/broken') {
        res.writeHead(500, { 'Content-Type': 'text/html' });
        res.end(next16Html);
        return;
      }
      res.writeHead(404);
      res.end();
    });

    try {
      const res = await runVibesane({ port: srv.port });
      assert.equal(res.ok, false);
      assert.ok(res.aiPrompt);

      const report = formatTerminalReport(res, { color: false });
      assert.ok(
        report.includes(
          "broken/page.tsx - TypeError: Cannot read properties of undefined (reading 'name')",
        ),
        `Esperava broken/page.tsx - TypeError no relatório:\n${report}`,
      );
      assert.equal(report.includes('__next_builtin__not-found.js'), false);
      assert.equal(report.includes('layout.tsx'), false);

      assert.ok(
        res.aiPrompt.includes(
          "broken/page.tsx - TypeError: Cannot read properties of undefined (reading 'name')",
        ),
      );
      assert.equal(res.aiPrompt.includes('__next_builtin__not-found.js'), false);
      assert.equal(res.aiPrompt.includes('layout.tsx'), false);
    } finally {
      await srv.close();
    }
  });

  it('4. Mascaramento de senhas (G*** e ***) e DATABASE_URL (postgres://user:****@host/db)', async () => {
    assert.equal(redactPassword('Goldsafe2026'), 'G***');
    assert.equal(redactPassword(''), '***');

    const rawDbUri = 'postgres://admin:mySecretPass@db.example.com:5432/appdb';
    const expectedMaskedUri = 'postgres://admin:****@db.example.com:5432/appdb';
    assert.equal(redactConnectionUri(rawDbUri), expectedMaskedUri);

    const payload = `
      const auth = { password: "Goldsafe2026" };
      const env = { DATABASE_URL: "${rawDbUri}" };
    `;
    const issues = scanSecrets(payload, '/src/config.ts');
    assert.equal(issues.length, 2);

    const prompt = generateAiFixPrompt({
      ok: false,
      port: 3000,
      url: 'http://localhost:3000',
      issues,
    });
    assert.ok(prompt);
    assert.ok(prompt.includes('G***'), `Esperava G*** no prompt:\n${prompt}`);
    assert.ok(
      prompt.includes(expectedMaskedUri),
      `Esperava ${expectedMaskedUri} no prompt:\n${prompt}`,
    );
    assert.equal(prompt.includes('Goldsafe2026'), false);
    assert.equal(prompt.includes('mySecretPass'), false);
  });

  it('5. Formato puro do prompt (zero ANSI mesmo com color: true), deduplicação e limite de 10 erros (...and N more)', () => {
    assert.equal(shouldEnableColor(true, true, { NO_COLOR: '1' }), false);
    assert.equal(shouldEnableColor(true, true, {}), true);

    const rawIssues = [];
    // Adiciona duplicatas do erro 1
    rawIssues.push({
      kind: 'http_error',
      severity: 'error',
      route: '/route-1?t=1730900000000',
      detail: 'HTTP 500 on route /route-1',
    });
    rawIssues.push({
      kind: 'http_error',
      severity: 'error',
      route: '/route-1',
      detail: 'HTTP 500 on route /route-1',
    });

    // Adiciona mais 12 erros únicos (totalizando 13 erros únicos e 14 itens brutos)
    for (let i = 2; i <= 13; i++) {
      rawIssues.push({
        kind: 'http_error',
        severity: 'error',
        route: `/route-${i}`,
        detail: `HTTP 500 on route /route-${i}`,
      });
    }

    const aiPrompt = generateAiFixPrompt({
      ok: false,
      port: 3000,
      url: 'http://localhost:3000',
      issues: rawIssues,
    });
    assert.ok(aiPrompt);
    assert.ok(aiPrompt.includes('Target: http://localhost:3000'));
    assert.ok(aiPrompt.includes('1. [http_error] HTTP 500 on route /route-1'));
    assert.ok(aiPrompt.includes('10. [http_error] HTTP 500 on route /route-10'));
    assert.equal(aiPrompt.includes('11. [http_error]'), false);
    assert.ok(aiPrompt.includes('...and 3 more'));
    assert.equal(/\x1b\[/.test(aiPrompt), false);

    const coloredReport = formatTerminalReport(
      {
        ok: false,
        port: 3000,
        url: 'http://localhost:3000',
        issues: rawIssues,
        aiPrompt,
        message: [
          'vibesane: sanity check failed on http://localhost:3000 (13 error(s))',
          'error [http_error]: HTTP 500 on route /route-1',
        ].join('\n'),
      },
      { color: true, isTTY: true, env: {} },
    );

    const promptSplitIdx = coloredReport.indexOf(AI_PROMPT_HEADER);
    assert.ok(promptSplitIdx !== -1);
    const promptSectionFromReport = coloredReport.slice(promptSplitIdx);

    // Garante zero códigos ANSI dentro do bloco do prompt de IA mesmo com color: true
    assert.equal(
      /\x1b\[/.test(promptSectionFromReport),
      false,
      'Bloco AI FIX PROMPT não pode conter sequências ANSI',
    );
  });

  describe('6. Resolução de módulo-fonte original dentro de chunks do Next (Turbopack e Webpack)', () => {
    it('6a. Cenário Turbopack: aponta para src/app/components/Checkout.tsx (último marcador antes da chave) e não para _1krgdap0boni4._.js nem Footer.tsx', async () => {
      const fakeKey = ['sk', 'live', '51H8abcDEF1234567890xyz9876'].join('_');
      const turbopackChunk = [
        '(globalThis.TURBOPACK = globalThis.TURBOPACK || []).push(["/_next/static/chunks/_1krgdap0boni4._.js", {',
        '"[project]/src/app/layout.tsx [app-client] (ecmascript)": ((__turbopack_context__) => {',
        '  const layoutTitle = "Safe Layout";',
        '}),',
        '"[project]/src/app/components/Checkout.tsx [app-client] (ecmascript)": ((__turbopack_context__) => {',
        `  const stripeSecret = "${fakeKey}";`,
        '  return stripeSecret;',
        '}),',
        '"[project]/src/app/components/Footer.tsx [app-client] (ecmascript)": ((__turbopack_context__) => {',
        '  const footerText = "Copyright 2026";',
        '}),',
        '}]);',
      ].join('\n');

      const matchIdx = turbopackChunk.indexOf(fakeKey);
      assert.equal(
        resolveBundledSourceFile(turbopackChunk, matchIdx),
        'src/app/components/Checkout.tsx',
      );

      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(
            '<html><head><script src="/_next/static/chunks/_1krgdap0boni4._.js"></script></head><body>App</body></html>',
          );
          return;
        }
        if (url === '/_next/static/chunks/_1krgdap0boni4._.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end(turbopackChunk);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, false);
        assert.equal(res.issues.length, 1);

        const issue = res.issues[0];
        assert.equal(issue.kind, 'secret_leak');
        assert.equal(issue.route, 'src/app/components/Checkout.tsx');
        assert.ok(issue.detail.includes('src/app/components/Checkout.tsx'));
        assert.equal(issue.detail.includes('_1krgdap0boni4._.js'), false);
        assert.equal(issue.detail.includes('Footer.tsx'), false);

        assert.ok(res.aiPrompt);
        assert.ok(res.aiPrompt.includes('src/app/components/Checkout.tsx'));
        assert.equal(res.aiPrompt.includes('_1krgdap0boni4._.js'), false);
        assert.equal(res.aiPrompt.includes('Footer.tsx'), false);
      } finally {
        await srv.close();
      }
    });

    it('6b. Cenário Webpack (next dev --webpack): aponta para src/app/components/PaymentForm.tsx', () => {
      const fakeKey = ['sk', 'live', '51H8abcDEF1234567890xyz9876'].join('_');
      const webpackChunk = [
        '(self["webpackChunk_N_E"] = self["webpackChunk_N_E"] || []).push([["app/page"],{',
        '/***/ "(app-pages-browser)/./node_modules/next/dist/client/app-next.js":',
        '/*!****************************************************************!***\\',
        '  !*** ./node_modules/next/dist/client/app-next.js ***!',
        '  \\****************************************************************/',
        '/***/ (function() { console.log("runtime"); }),',
        '/***/ "(app-pages-browser)/./src/app/components/Header.tsx":',
        '/***/ (function() { return "Header"; }),',
        '/***/ "(app-pages-browser)/./src/app/components/PaymentForm.tsx":',
        `/***/ (function() { const key = "${fakeKey}"; return key; }),`,
        '/***/ "(app-pages-browser)/./src/app/page.tsx":',
        '/***/ (function() { return "Page"; })',
        '}]);',
      ].join('\n');

      const issues = scanSecrets(webpackChunk, '/_next/static/chunks/app/page.js');
      assert.equal(issues.length, 1);
      assert.equal(issues[0].route, 'src/app/components/PaymentForm.tsx');
      assert.ok(issues[0].detail.includes('src/app/components/PaymentForm.tsx'));
      assert.equal(issues[0].detail.includes('/_next/static/chunks/app/page.js'), false);
      assert.equal(issues[0].detail.includes('Header.tsx'), false);
      assert.equal(issues[0].detail.includes('src/app/page.tsx'), false);

      const prompt = generateAiFixPrompt({
        ok: false,
        port: 3000,
        url: 'http://localhost:3000',
        issues,
      });
      assert.ok(prompt);
      assert.ok(
        prompt.includes(
          '1. [secret_leak] Secret leak on src/app/components/PaymentForm.tsx: Stripe secret key (sk_live_****9876)',
        ),
      );
      assert.equal(
        prompt.includes('src/app/components/PaymentForm.tsx — Secret leak'),
        false,
      );
      assert.equal(prompt.includes('/_next/static/chunks/app/page.js'), false);
    });

    it('6c. Cenário Webpack eval("...") com aspas escapadas (\\"): detecta password (G***), DATABASE_URL (postgres://admin:****@...) e *_SECRET', () => {
      const webpackEvalChunk = [
        '/***/ "(app-pages-browser)/./src/app/components/Checkout.tsx":',
        '/***/ (function(module, __webpack_exports__, __webpack_require__) {',
        'eval("const cfg = {\\n    password: \\"Goldsafe2026\\",\\n    DATABASE_URL: \\"postgres://admin:mySecretPass@db.internal:5432/prod\\",\\n    JWT_SECRET: \\"superSecretJwtValue99\\"\\n};\\n//# sourceURL=webpack-internal:///(app-pages-browser)/./src/app/components/Checkout.tsx\\n");',
        '/***/ })',
      ].join('\n');

      const issues = scanSecrets(webpackEvalChunk, '/_next/static/chunks/app/page.js');
      assert.equal(issues.length, 3);

      for (const issue of issues) {
        assert.equal(issue.route, 'src/app/components/Checkout.tsx');
        assert.equal(issue.detail.includes('Goldsafe2026'), false);
        assert.equal(issue.detail.includes('mySecretPass'), false);
        assert.equal(issue.detail.includes('superSecretJwtValue99'), false);
        assert.equal((issue.maskedSnippet ?? '').endsWith('\\'), false);
      }

      const pwdIssue = issues.find((i) => i.detail.includes('Hardcoded password'));
      assert.ok(pwdIssue, 'Deve detectar password com aspas escapadas');
      assert.equal(pwdIssue.maskedSnippet, 'G***');

      const dbIssue = issues.find((i) => i.detail.includes('DATABASE_URL'));
      assert.ok(dbIssue, 'Deve detectar DATABASE_URL com aspas escapadas');
      assert.equal(dbIssue.maskedSnippet, 'postgres://admin:****@db.internal:5432/prod');

      const jwtIssue = issues.find((i) => i.detail.includes('JWT_SECRET'));
      assert.ok(jwtIssue, 'Deve detectar JWT_SECRET com aspas escapadas');
      assert.equal(jwtIssue.maskedSnippet, 'sup****99');
    });
  });

  it('7. Fixture real capturada do Vite 8 (test/fixtures/vite8-oxc-syntax-error.js) + invariante 100% ASCII (/^[\\t\\n\\x20-\\x7E]*$/)', async () => {
    const fixtureUrl = new URL('./fixtures/vite8-oxc-syntax-error.js', import.meta.url);
    const rawFixture = fs.readFileSync(fixtureUrl, 'utf8');
    const fakeKey = ['sk', 'live', '11112222333344445555abcd'].join('_');
    const expectedMasked = ['sk', 'live', '****abcd'].join('_');
    const fixtureWithSecret = rawFixture.replaceAll('__VIBESANE_TEST_STRIPE_KEY__', fakeKey);

    const srv = await startHttpServer((req, res) => {
      const url = req.url ?? '/';
      if (url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><body><script type="module" src="/src/main.tsx"></script></body></html>');
        return;
      }
      if (url === '/src/main.tsx') {
        res.writeHead(200, { 'Content-Type': 'application/javascript' });
        res.end('import { Pay } from "./components/Pay.tsx";\nconsole.log(Pay);\n');
        return;
      }
      if (url === '/src/components/Pay.tsx') {
        res.writeHead(500, { 'Content-Type': 'text/html' });
        res.end(fixtureWithSecret);
        return;
      }
      res.writeHead(404);
      res.end();
    });

    try {
      const res = await runVibesane({ port: srv.port });
      assert.equal(res.ok, false);
      assert.ok(res.aiPrompt, 'res.aiPrompt deve existir');

      const report = formatTerminalReport(res, { color: false });

      // Target URL explícito
      assert.ok(
        res.aiPrompt.includes(`Target: http://localhost:${srv.port}`),
        `Esperava Target URL no prompt:\n${res.aiPrompt}`,
      );

      // O Vite 8.3.6 real não envia loc, mas extractViteErrorInfo extrai :2:98 do cabeçalho da moldura Oxc e promove [PARSE_ERROR] ... para o resumo
      const promptLines = res.aiPrompt.split('\n');
      const httpErrorLineIdx = promptLines.findIndex((l) => l.startsWith('1. [http_error]'));
      assert.notEqual(httpErrorLineIdx, -1, `Linha 1. [http_error] não encontrada em:\n${res.aiPrompt}`);
      const httpErrorLine = promptLines[httpErrorLineIdx];
      assert.equal(
        httpErrorLine,
        '1. [http_error] HTTP 500 on script /src/components/Pay.tsx:2:98 - [PARSE_ERROR] Expected `,` or `}` but found `Identifier`',
      );
      const occurrencesInErrorLine = httpErrorLine.split('/src/components/Pay.tsx').length - 1;
      assert.equal(
        occurrencesInErrorLine,
        1,
        `Esperava /src/components/Pay.tsx apenas 1 vez na linha do erro, obtido ${occurrencesInErrorLine}: ${httpErrorLine}`,
      );

      // Verifica que [PARSE_ERROR] ... está no resumo e não aparece duplicado no codeFrame (que começa na moldura +-[ src/components/Pay.tsx:2:98 ] e termina em ---+)
      const httpIssue = res.issues.find(
        (i) => i.kind === 'http_error' && i.route === '/src/components/Pay.tsx',
      );
      assert.ok(httpIssue?.codeFrame, 'httpIssue.codeFrame deve existir');
      assert.equal(
        httpIssue.codeFrame.includes('[PARSE_ERROR]'),
        false,
        `[PARSE_ERROR] não deve aparecer duplicado no codeFrame:\n${httpIssue.codeFrame}`,
      );
      assert.match(httpIssue.codeFrame, /^\s*\+-\[\s*src\/components\/Pay\.tsx:2:98\s*\]/);
      assert.match(httpIssue.codeFrame, /---\+$/);
      assert.equal(
        res.aiPrompt.split('[PARSE_ERROR]').length - 1,
        1,
        `[PARSE_ERROR] deve aparecer apenas 1 vez no aiPrompt:\n${res.aiPrompt}`,
      );
      assert.equal(
        promptLines[httpErrorLineIdx + 1]?.trim(),
        '+-[ src/components/Pay.tsx:2:98 ]',
        `A primeira linha do codeFrame logo abaixo de 1. [http_error] deve ser a moldura +-[ ... ]:\n${res.aiPrompt}`,
      );
      assert.ok(
        report.includes(
          'HTTP 500 on script /src/components/Pay.tsx:2:98 - [PARSE_ERROR] Expected `,` or `}` but found `Identifier`',
        ),
        `Esperava resumo completo no report:\n${report}`,
      );

      // CodeFrame multilinhas do Vite 8 (Oxc) extraído de payload.message, molduras ASCII (+, -, |), posição 2:98 na moldura, sem /workspace/app e chave mascarada
      assert.ok(res.aiPrompt.includes('[PARSE_ERROR]'));
      assert.ok(
        res.aiPrompt.includes('+-[ src/components/Pay.tsx:2:98 ]'),
        `Esperava moldura ASCII +-[ src/components/Pay.tsx:2:98 ] em:\n${res.aiPrompt}`,
      );
      assert.ok(res.aiPrompt.includes('2 |   const broken ='));
      assert.ok(res.aiPrompt.includes('Olá, senha inválida'));
      assert.ok(res.aiPrompt.includes('---+'), `Esperava fechamento ASCII ---+ em:\n${res.aiPrompt}`);
      assert.equal(res.aiPrompt.includes('/workspace/app'), false);
      assert.equal(report.includes('/workspace/app'), false);
      assert.ok(res.aiPrompt.includes(expectedMasked));
      assert.equal(res.aiPrompt.includes('11112222333344445555'), false);
      assert.equal(report.includes('11112222333344445555'), false);

      // Invariante 100% ASCII para tudo que o vibesane e as molduras do Vite geram (exceto o literal acentuado do código do usuário)
      assert.match(report.replaceAll('Olá, senha inválida', 'Ola, senha invalida'), /^[\t\n\x20-\x7E]*$/);
      assert.match(
        res.aiPrompt.replaceAll('Olá, senha inválida', 'Ola, senha invalida'),
        /^[\t\n\x20-\x7E]*$/,
      );
    } finally {
      await srv.close();
    }
  });

  it('8. Preservação de acentos do código do usuário (const msg = "Olá, senha inválida") ao converter molduras Unicode para ASCII', () => {
    const rawWithAccentsAndBoxes = [
      '× Transform failed — syntax error · line 2',
      '   ╭─[ src/components/Login.tsx:2:15 ]',
      '   │',
      ' 2 │   const msg = "Olá, senha inválida";',
      '   │               ╰── unexpected token',
      '───╯',
    ].join('\n');

    const asciiNormalized = toAsciiSafe(rawWithAccentsAndBoxes);
    assert.ok(asciiNormalized.includes('x Transform failed - syntax error : line 2'));
    assert.ok(asciiNormalized.includes('+-[ src/components/Login.tsx:2:15 ]'));
    assert.ok(asciiNormalized.includes('2 |   const msg = "Olá, senha inválida";'));
    assert.ok(asciiNormalized.includes('+-- unexpected token'));
    assert.ok(asciiNormalized.includes('---+'));
    assert.equal(asciiNormalized.includes('?'), false);

    const vitePayload = {
      message: rawWithAccentsAndBoxes,
      id: '/workspace/app/src/components/Login.tsx',
      frame: '',
      plugin: 'vite:oxc',
      loc: {
        file: '/workspace/app/src/components/Login.tsx',
        line: 2,
        column: 15,
      },
    };
    const rawViteResponse = `const error = ${JSON.stringify(vitePayload)};`;
    const info = extractViteErrorInfo(rawViteResponse, '/src/components/Login.tsx');
    assert.ok(info);
    assert.ok(info.codeFrame);
    assert.ok(info.codeFrame.includes('const msg = "Olá, senha inválida";'));
    assert.ok(info.codeFrame.includes('+-[ src/components/Login.tsx:2:15 ]'));
    assert.equal(info.codeFrame.includes('╭'), false);
    assert.equal(info.codeFrame.includes('│'), false);

    const prompt = generateAiFixPrompt({
      ok: false,
      port: 5173,
      url: 'http://localhost:5173',
      issues: [
        {
          kind: 'http_error',
          severity: 'error',
          route: '/src/components/Login.tsx',
          detail: `HTTP 500 on script ${info.summary}`,
          codeFrame: info.codeFrame,
        },
      ],
    });
    assert.ok(prompt);
    assert.ok(prompt.includes('const msg = "Olá, senha inválida";'));
    assert.equal(prompt.includes('?'), false);
  });

  it('9. Fronteiras de detailContainsRoute e escape de regex (/ vs postgres://..., / em /api/items, e Pay.tsx vs Pay-tsx)', () => {
    // Caso 1: '/' com espaço antes e ':' depois -> true
    assert.equal(
      detailContainsRoute(
        'Secret leak on /: DATABASE_URL (postgres://admin:****@db.example.com:5432/appdb)',
        '/',
      ),
      true,
    );

    // Caso 2: '/' não casa com as barras internas de 'postgres://' nem '/appdb' -> false
    const dbDetailWithoutRoute =
      'DATABASE_URL leaked (postgres://admin:****@db.example.com:5432/appdb)';
    assert.equal(detailContainsRoute(dbDetailWithoutRoute, '/'), false);

    const dbPrompt = generateAiFixPrompt({
      ok: false,
      port: 3000,
      url: 'http://localhost:3000',
      issues: [
        {
          kind: 'secret_leak',
          severity: 'error',
          route: '/',
          detail: dbDetailWithoutRoute,
        },
      ],
    });
    assert.ok(dbPrompt);
    assert.ok(
      dbPrompt.includes(
        `1. [secret_leak] / - ${dbDetailWithoutRoute}`,
      ),
      `Esperava prefixo "/ - " no prompt:\n${dbPrompt}`,
    );

    // Caso 3: '/' não casa com o prefixo de '/api/items' -> false
    const subPathDetail = 'Unhandled error in /api/items';
    assert.equal(detailContainsRoute(subPathDetail, '/'), false);

    const subPathPrompt = generateAiFixPrompt({
      ok: false,
      port: 3000,
      url: 'http://localhost:3000',
      issues: [
        {
          kind: 'http_error',
          severity: 'error',
          route: '/',
          detail: subPathDetail,
        },
      ],
    });
    assert.ok(subPathPrompt);
    assert.ok(
      subPathPrompt.includes('1. [http_error] / - Unhandled error in /api/items'),
      `Esperava "1. [http_error] / - Unhandled error in /api/items" no prompt:\n${subPathPrompt}`,
    );

    // Caso 4: '.' em '/src/Pay.tsx' está escapado e não casa com '/src/Pay-tsx' -> false
    assert.equal(
      detailContainsRoute('HTTP 500 on script /src/Pay-tsx', '/src/Pay.tsx'),
      false,
    );
  });

  it('10. Paridade texto puro vs JSON Oxc, precedência de payload.loc, falsos positivos [x:1:2]/arr[a:2:3] e N > 1 causas', () => {
    const oxcPlainText = [
      'Transform failed with 1 error:',
      '',
      '[PARSE_ERROR] Expected `,` or `}` but found `Identifier`',
      '   ╭─[ src/components/Pay.tsx:2:98 ]',
      '   │',
      ' 2 │   const broken = { msg: "Olá, senha inválida" b: 2 };',
      '   │                  ┬                            ┬  ',
      '   │                  ╰────────────────────────────── Opened here',
      '   │                                               │  ',
      '   │                                               ╰── `,` or `}` expected',
      '───╯',
    ].join('\n');

    // 10a. Paridade texto puro vs JSON
    const fromPlain = extractViteErrorInfo(oxcPlainText, '/src/components/Pay.tsx');
    const fromJson = extractViteErrorInfo(
      `const error = ${JSON.stringify({ message: oxcPlainText, id: '/workspace/app/src/components/Pay.tsx', frame: '', plugin: 'vite:oxc' })};`,
      '/src/components/Pay.tsx',
    );
    assert.ok(fromPlain);
    assert.ok(fromJson);
    assert.equal(
      fromPlain.summary,
      '/src/components/Pay.tsx:2:98 - [PARSE_ERROR] Expected `,` or `}` but found `Identifier`',
    );
    assert.equal(fromPlain.summary, fromJson.summary);
    assert.ok(fromPlain.codeFrame);
    assert.equal(fromPlain.codeFrame, fromJson.codeFrame);
    assert.match(fromPlain.codeFrame, /^\s*\+-\[\s*src\/components\/Pay\.tsx:2:98\s*\]/);
    assert.match(fromPlain.codeFrame, /---\+$/);
    assert.equal(fromPlain.codeFrame.includes('[PARSE_ERROR]'), false);

    // 10b. Teste negativo 1: payload.loc presente vence sobre o L:C da moldura Oxc
    const withLocOverride = extractViteErrorInfo(
      `const error = ${JSON.stringify({
        message: oxcPlainText,
        id: '/workspace/app/src/components/Pay.tsx',
        loc: { file: '/workspace/app/src/components/Pay.tsx', line: 10, column: 5 },
      })};`,
      '/src/components/Pay.tsx',
    );
    assert.ok(withLocOverride);
    assert.equal(
      withLocOverride.summary,
      '/src/components/Pay.tsx:10:5 - [PARSE_ERROR] Expected `,` or `}` but found `Identifier`',
    );

    // 10c. Teste negativo 2: código do usuário com [x:1:2] e arr[a:2:3] sem moldura ╭─[ / +-[ e sem payload.loc
    const fakeBracketText = [
      'Transform failed with 1 error:',
      '[PARSE_ERROR] Unexpected token in [x:1:2]',
      ' 2 | const val = arr[a:2:3]; [x:1:2]',
      '   |                 ^',
    ].join('\n');
    const jsonNoFrameHeader = extractViteErrorInfo(
      `const error = ${JSON.stringify({ message: fakeBracketText, id: '/src/components/Pay.tsx' })};`,
      '/src/components/Pay.tsx',
    );
    const plainNoFrameHeader = extractViteErrorInfo(fakeBracketText, '/src/components/Pay.tsx');
    assert.ok(jsonNoFrameHeader);
    assert.ok(plainNoFrameHeader);
    assert.equal(
      jsonNoFrameHeader.summary,
      '/src/components/Pay.tsx - [PARSE_ERROR] Unexpected token in [x:1:2]',
    );
    assert.equal(plainNoFrameHeader.summary, jsonNoFrameHeader.summary);
    assert.equal(jsonNoFrameHeader.summary.includes('/src/components/Pay.tsx:1:2'), false);
    assert.equal(jsonNoFrameHeader.summary.includes('/src/components/Pay.tsx:2:3'), false);

    // 10d. Teste N > 1 causas: promove apenas a 1ª causa para o summary e mantém a 2ª no codeFrame
    const multiCauseText = [
      'Transform failed with 2 errors:',
      '',
      '[PARSE_ERROR] First error',
      '   ╭─[ src/components/Pay.tsx:2:10 ]',
      '   │',
      ' 2 │   const a = ;',
      '───╯',
      '[PARSE_ERROR] Second error',
      '   ╭─[ src/components/Pay.tsx:5:4 ]',
      '   │',
      ' 5 │   const b = ;',
      '───╯',
    ].join('\n');
    const multiJson = extractViteErrorInfo(
      `const error = ${JSON.stringify({ message: multiCauseText, id: '/src/components/Pay.tsx' })};`,
      '/src/components/Pay.tsx',
    );
    const multiPlain = extractViteErrorInfo(multiCauseText, '/src/components/Pay.tsx');
    assert.ok(multiJson);
    assert.ok(multiPlain);
    assert.equal(
      multiJson.summary,
      '/src/components/Pay.tsx:2:10 - [PARSE_ERROR] First error',
    );
    assert.equal(multiPlain.summary, multiJson.summary);
    assert.ok(multiJson.codeFrame);
    assert.ok(multiPlain.codeFrame);
    assert.equal(multiJson.codeFrame.includes('[PARSE_ERROR] First error'), false);
    assert.ok(multiJson.codeFrame.includes('[PARSE_ERROR] Second error'));
    assert.equal(multiPlain.codeFrame.includes('[PARSE_ERROR] First error'), false);
    assert.ok(multiPlain.codeFrame.includes('[PARSE_ERROR] Second error'));
  });
});

describe('v0.1.2 - Mascaramento de URIs de banco no codeFrame e mensagens de erro (Vite/Oxc & Next)', () => {
  it('11. Oxc/Vite (JSON e fallback texto puro): mascara senhas em postgres://, postgresql://, mysql:// e mongodb+srv:// mantendo o esquema intacto no summary, codeFrame e prompt', () => {
    const pgPass = ['pg', 'Secret', 'Pass', '111'].join('');
    const pgsqlPass = ['pgsql', 'Secret', 'Pass', '222'].join('');
    const mysqlPass = ['mysql', 'Secret', 'Pass', '333'].join('');
    const mongoPass = ['mongo', 'Secret', 'Pass', '444'].join('');

    const rawOxcMessage = [
      'Transform failed with 1 error:',
      '',
      `[PARSE_ERROR] Connection failed for "postgres://admin:${pgPass}@db:5432/p" and "postgresql://u:${pgsqlPass}@h:5432/d"`,
      '   ╭─[ src/db.ts:4:15 ]',
      '   │',
      ` 2 │   const pg = "postgres://admin:${pgPass}@db:5432/p";`,
      ` 3 │   const pgsql = "postgresql://u:${pgsqlPass}@h:5432/d";`,
      ` 4 │   const my = "mysql://root:${mysqlPass}@db:3306/app" broken`,
      ` 5 │   const mg = "mongodb+srv://u:${mongoPass}@c.x.net/db";`,
      '───╯',
    ].join('\n');

    const jsonPayload = `const error = ${JSON.stringify({
      message: rawOxcMessage,
      id: 'C:/Users/alex/proj/src/db.ts',
      frame: '',
      plugin: 'vite:oxc',
    })};`;

    const fromJson = extractViteErrorInfo(jsonPayload, '/src/db.ts');
    const fromPlain = extractViteErrorInfo(rawOxcMessage, '/src/db.ts');

    for (const [label, info] of [
      ['JSON', fromJson],
      ['Plain', fromPlain],
    ]) {
      assert.ok(info, `${label}: info deve existir`);
      assert.ok(info.codeFrame, `${label}: codeFrame deve existir`);

      // Esquemas intactos e senhas mascaradas no summary
      assert.ok(
        info.summary.includes('postgres://admin:****@db:5432/p'),
        `${label} summary deve conter postgres://admin:****@db:5432/p:\n${info.summary}`,
      );
      assert.ok(
        info.summary.includes('postgresql://u:****@h:5432/d'),
        `${label} summary deve conter postgresql://u:****@h:5432/d:\n${info.summary}`,
      );

      // Esquemas intactos e senhas mascaradas no codeFrame
      assert.ok(
        info.codeFrame.includes('"postgres://admin:****@db:5432/p"'),
        `${label} codeFrame deve conter "postgres://admin:****@db:5432/p":\n${info.codeFrame}`,
      );
      assert.ok(
        info.codeFrame.includes('"postgresql://u:****@h:5432/d"'),
        `${label} codeFrame deve conter "postgresql://u:****@h:5432/d":\n${info.codeFrame}`,
      );
      assert.ok(
        info.codeFrame.includes('"mysql://root:****@db:3306/app"'),
        `${label} codeFrame deve conter "mysql://root:****@db:3306/app":\n${info.codeFrame}`,
      );
      assert.ok(
        info.codeFrame.includes('"mongodb+srv://u:****@c.x.net/db"'),
        `${label} codeFrame deve conter "mongodb+srv://u:****@c.x.net/db":\n${info.codeFrame}`,
      );

      // Senhas originais nunca aparecem
      for (const secret of [pgPass, pgsqlPass, mysqlPass, mongoPass]) {
        assert.equal(info.summary.includes(secret), false, `${label} summary vazou ${secret}`);
        assert.equal(info.codeFrame.includes(secret), false, `${label} codeFrame vazou ${secret}`);
      }

      const prompt = generateAiFixPrompt({
        ok: false,
        port: 5173,
        url: 'http://localhost:5173',
        issues: [
          {
            kind: 'http_error',
            severity: 'error',
            route: '/src/db.ts',
            detail: `HTTP 500 on script ${info.summary}`,
            codeFrame: info.codeFrame,
          },
        ],
      });
      assert.ok(prompt);
      assert.ok(prompt.includes('"postgres://admin:****@db:5432/p"'));
      assert.ok(prompt.includes('"postgresql://u:****@h:5432/d"'));
      assert.ok(prompt.includes('"mysql://root:****@db:3306/app"'));
      assert.ok(prompt.includes('"mongodb+srv://u:****@c.x.net/db"'));
      for (const secret of [pgPass, pgsqlPass, mysqlPass, mongoPass]) {
        assert.equal(prompt.includes(secret), false, `${label} prompt vazou ${secret}`);
      }
    }
  });

  it('12. Next (extractNextErrorInfo): mascara senhas em postgres://, postgresql://, mysql:// e mongodb+srv:// mantendo o esquema intacto', () => {
    const pgPass = ['pg', 'Next', 'Pass', '111'].join('');
    const pgsqlPass = ['pgsql', 'Next', 'Pass', '222'].join('');
    const mysqlPass = ['mysql', 'Next', 'Pass', '333'].join('');
    const mongoPass = ['mongo', 'Next', 'Pass', '444'].join('');

    const nextHtml = `
      <script>
        self.__next_f.push([1,"1:{\\"type\\":\\"page\\",\\"pagePath\\":\\"src/app/db/page.tsx\\"}\\n"]);
        self.__next_f.push([1,"2:{\\"name\\":\\"Error\\",\\"message\\":\\"DB errors: postgres://admin:${pgPass}@db:5432/p | postgresql://u:${pgsqlPass}@h:5432/d | mysql://root:${mysqlPass}@db:3306/app | mongodb+srv://u:${mongoPass}@c.x.net/db\\"}\\n"]);
      </script>
    `;

    const extracted = extractNextErrorInfo(nextHtml, '/db');
    assert.ok(extracted);
    assert.ok(extracted.summary.includes('postgres://admin:****@db:5432/p'));
    assert.ok(extracted.summary.includes('postgresql://u:****@h:5432/d'));
    assert.ok(extracted.summary.includes('mysql://root:****@db:3306/app'));
    assert.ok(extracted.summary.includes('mongodb+srv://u:****@c.x.net/db'));

    for (const secret of [pgPass, pgsqlPass, mysqlPass, mongoPass]) {
      assert.equal(extracted.summary.includes(secret), false);
    }
  });

  it('13. Regressão: caminhos absolutos Windows (C:\\Users\\alex\\proj\\src\\db.ts, D:/work/app/src/index.ts) e Unix (/Users/alex/proj/src/db.ts) + chave Stripe sk_live_ e acentos UTF-8 ("Olá") no codeFrame', () => {
    const fakeStripeKey = ['sk', 'live', '99887766554433221100zyxw'].join('_');
    const expectedMaskedStripe = ['sk', 'live', '****zyxw'].join('_');
    const dbPass = ['my', 'Top', 'Secret', '99'].join('');

    const frameWithPathsAndSecrets = [
      '   ╭─[ C:\\Users\\alex\\proj\\src\\db.ts:3:10 ]',
      '   │',
      ' 1 │ // Imported from D:/work/app/src/index.ts and /Users/alex/proj/src/db.ts',
      ` 2 │ const stripe = "${fakeStripeKey}";`,
      ` 3 │ const db = "postgres://admin:${dbPass}@db:5432/p";`,
      ' 4 │ const greeting = "Olá";',
      '───╯',
    ].join('\n');

    const payload = {
      message:
        'Transform failed in C:\\Users\\alex\\proj\\src\\db.ts (imported by D:/work/app/src/index.ts and /Users/alex/proj/src/db.ts)',
      id: 'C:\\Users\\alex\\proj\\src\\db.ts',
      frame: frameWithPathsAndSecrets,
      loc: {
        file: 'C:\\Users\\alex\\proj\\src\\db.ts',
        line: 3,
        column: 10,
      },
    };

    const info = extractViteErrorInfo(`const error = ${JSON.stringify(payload)};`, '/src/db.ts');
    assert.ok(info);
    assert.ok(info.codeFrame);

    // Caminhos absolutos limpos na mensagem e no frame
    for (const forbidden of ['C:\\Users\\alex', 'C:/Users/alex', 'D:/work/app', '/Users/alex']) {
      assert.equal(
        info.summary.includes(forbidden),
        false,
        `summary não deve conter ${forbidden}: ${info.summary}`,
      );
      assert.equal(
        info.codeFrame.includes(forbidden),
        false,
        `codeFrame não deve conter ${forbidden}:\n${info.codeFrame}`,
      );
    }
    assert.ok(info.summary.includes('/src/db.ts'));
    assert.ok(info.summary.includes('/src/index.ts'));
    assert.ok(info.codeFrame.includes('/src/db.ts:3:10'));
    assert.ok(info.codeFrame.includes('/src/index.ts'));

    // Chave Stripe mascarada, URI de banco mascarada com esquema intacto e acento UTF-8 "Olá" preservado
    assert.ok(info.codeFrame.includes(expectedMaskedStripe));
    assert.equal(info.codeFrame.includes('99887766554433221100'), false);
    assert.ok(info.codeFrame.includes('"postgres://admin:****@db:5432/p"'));
    assert.equal(info.codeFrame.includes(dbPass), false);
    assert.ok(info.codeFrame.includes('const greeting = "Olá";'));
  });

  it('14. terminal-ui: formata warning [truncated_body] com prefixo correto e aplica cor amarela com TTY', () => {
    const reportInput = {
      ok: true,
      port: 3000,
      url: 'http://localhost:3000',
      message: [
        'vibesane: connected to http://localhost:3000 (15ms)',
        'warning [truncated_body]: response body truncated on script /app.js (exceeded 8 MB limit)',
      ].join('\n'),
      issues: [
        {
          kind: 'truncated_body',
          severity: 'warning',
          route: '/app.js',
          detail: 'response body truncated on script /app.js (exceeded 8 MB limit)',
        },
      ],
      aiPrompt: null,
    };

    const plain = formatTerminalReport(reportInput, { color: false });
    assert.ok(plain.includes('warning [truncated_body]: response body truncated on script /app.js (exceeded 8 MB limit)'));
    assert.equal(plain.includes('\x1b['), false);

    const prevForceColor = process.env.FORCE_COLOR;
    process.env.FORCE_COLOR = '1';
    try {
      const colored = formatTerminalReport(reportInput, { color: true, isTTY: true, env: { FORCE_COLOR: '1' } });
      assert.ok(colored.includes('warning [truncated_body]'));
      assert.ok(colored.includes('\x1b[33mwarning [truncated_body]'));
    } finally {
      if (prevForceColor === undefined) {
        delete process.env.FORCE_COLOR;
      } else {
        process.env.FORCE_COLOR = prevForceColor;
      }
    }
  });

  it('15. ai-prompt-gen: ignora issues de severidade "warning" (truncated_body) e não polui o prompt da IA', () => {
    const inputWithOnlyWarning = {
      port: 3000,
      url: 'http://localhost:3000',
      issues: [
        {
          kind: 'truncated_body',
          severity: 'warning',
          route: '/app.js',
          detail: 'response body truncated on script /app.js (exceeded 8 MB limit)',
        },
      ],
    };

    const prompt = generateAiFixPrompt(inputWithOnlyWarning);
    assert.equal(prompt, null, 'Prompt deve ser null quando houver apenas warnings');

    const fakeKey = ['sk', 'live', 'abcdefghijklmnopqrstuvwx'].join('_');
    const inputWithMixed = {
      port: 3000,
      url: 'http://localhost:3000',
      issues: [
        {
          kind: 'truncated_body',
          severity: 'warning',
          route: '/app.js',
          detail: 'response body truncated on script /app.js (exceeded 8 MB limit)',
        },
        {
          kind: 'secret_leak',
          severity: 'error',
          route: '/app.js',
          detail: `Secret leak on /app.js: Stripe secret key (${fakeKey})`,
        },
      ],
    };

    const mixedPrompt = generateAiFixPrompt(inputWithMixed);
    assert.ok(mixedPrompt);
    assert.ok(mixedPrompt.includes('[secret_leak]'));
    assert.equal(mixedPrompt.includes('truncated_body'), false, 'Não deve conter truncated_body no prompt da IA');
  });
});
