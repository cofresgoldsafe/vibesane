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

      // O Vite 8.3.6 real não envia loc, então a linha do erro fica sem :line:col e a posição 2:98 aparece na moldura
      const promptLines = res.aiPrompt.split('\n');
      const httpErrorLine = promptLines.find((l) => l.startsWith('1. [http_error]'));
      assert.ok(httpErrorLine, `Linha 1. [http_error] não encontrada em:\n${res.aiPrompt}`);
      assert.equal(
        httpErrorLine,
        '1. [http_error] HTTP 500 on script /src/components/Pay.tsx - Transform failed with 1 error:',
      );
      const occurrencesInErrorLine = httpErrorLine.split('/src/components/Pay.tsx').length - 1;
      assert.equal(
        occurrencesInErrorLine,
        1,
        `Esperava /src/components/Pay.tsx apenas 1 vez na linha do erro, obtido ${occurrencesInErrorLine}: ${httpErrorLine}`,
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
});
