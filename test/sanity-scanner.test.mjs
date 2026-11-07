import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { main } from '../dist/cli.js';
import {
  runVibesane,
  EXIT_CODES,
  redactSecret,
  detectMaskedError,
  scanSecrets,
  selectScriptsToFetch,
  formatTerminalReport,
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

describe('Sanity Scanner Engine (BDD)', () => {
  it('1. Zero duplo GET / e isenção de slow_route na raiz', async () => {
    let rootHits = 0;
    const srv = await startHttpServer((req, res) => {
      if (req.url === '/' || req.url === '') {
        rootHits += 1;
        setTimeout(() => {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><h1>Home</h1></body></html>');
        }, 120);
        return;
      }
      res.writeHead(404);
      res.end('Not Found');
    });

    try {
      const res = await runVibesane({ port: srv.port, slowRouteMs: 50 });
      assert.equal(rootHits, 1, 'Raiz / deve ser requisitada apenas uma vez');
      assert.equal(res.ok, true);
      assert.deepEqual(res.issues, []);
      assert.equal(res.routes.length, 1);
      assert.equal(res.routes[0].path, '/');
    } finally {
      await srv.close();
    }
  });

  it('2. Descoberta de sub-rotas <a href> e detecção de status 500 e 404 (ignorando externos e #)', async () => {
    const requestedPaths = [];
    const srv = await startHttpServer((req, res) => {
      const url = req.url ?? '/';
      requestedPaths.push(url);

      if (url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
          <html>
            <body>
              <a href="/ok">OK</a>
              <a href="/err500">Error 500</a>
              <a href="/missing">Missing 404</a>
              <a href="https://example.com/ext">External</a>
              <a href="mailto:test@example.com">Mail</a>
              <a href="#section">Hash</a>
            </body>
          </html>
        `);
        return;
      }
      if (url === '/ok') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body>OK route</body></html>');
        return;
      }
      if (url === '/err500') {
        res.writeHead(500, { 'Content-Type': 'text/html' });
        res.end('<html><body>Server Crash</body></html>');
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end('<html><body>Not Found</body></html>');
    });

    try {
      const res = await runVibesane({ port: srv.port });
      assert.equal(res.ok, false);

      assert.ok(requestedPaths.includes('/ok'));
      assert.ok(requestedPaths.includes('/err500'));
      assert.ok(requestedPaths.includes('/missing'));
      assert.equal(
        requestedPaths.some((p) => p.includes('example.com') || p.includes('#section')),
        false,
      );

      const err500Issue = res.issues.find(
        (i) => i.route === '/err500' && i.kind === 'http_error',
      );
      const err404Issue = res.issues.find(
        (i) => i.route === '/missing' && i.kind === 'http_error',
      );

      assert.ok(err500Issue, 'Deve reportar http_error para /err500');
      assert.equal(err500Issue.severity, 'error');
      assert.equal(err500Issue.statusCode, 500);

      assert.ok(err404Issue, 'Deve reportar http_error para /missing');
      assert.equal(err404Issue.severity, 'error');
      assert.equal(err404Issue.statusCode, 404);

      const cliRes = await runCli(['--port', String(srv.port)]);
      assert.equal(cliRes.code, EXIT_CODES.SANITY_FAILURE);
      assert.equal(cliRes.code, 1);
      assert.equal(cliRes.stderr, '');
      assert.match(cliRes.stdout, /sanity check failed/);
    } finally {
      await srv.close();
    }
  });

  describe('3. Redirects Location da mesma origem (até 3 saltos) vs externos', () => {
    it('3a. segue redirect 302 da mesma origem (/old -> /new 200 OK) e ignora redirect externo sem falhar', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <html><body>
              <a href="/old">Old</a>
              <a href="/ext-redirect">External Redirect</a>
            </body></html>
          `);
          return;
        }
        if (url === '/old') {
          res.writeHead(302, { Location: '/new' });
          res.end();
          return;
        }
        if (url === '/new') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body>New Destination</body></html>');
          return;
        }
        if (url === '/ext-redirect') {
          res.writeHead(302, { Location: 'https://external.example.com/login' });
          res.end();
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        assert.deepEqual(res.issues, []);
      } finally {
        await srv.close();
      }
    });

    it('3b. falha quando sub-rota excede 3 redirects (/loop)', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><a href="/loop1">Loop</a></body></html>');
          return;
        }
        if (url === '/loop1') {
          res.writeHead(302, { Location: '/loop2' });
          res.end();
          return;
        }
        if (url === '/loop2') {
          res.writeHead(302, { Location: '/loop3' });
          res.end();
          return;
        }
        if (url === '/loop3') {
          res.writeHead(302, { Location: '/loop4' });
          res.end();
          return;
        }
        if (url === '/loop4') {
          res.writeHead(302, { Location: '/loop1' });
          res.end();
          return;
        }
        res.writeHead(200);
        res.end('ok');
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, false);
        const loopIssue = res.issues.find((i) => i.route === '/loop1');
        assert.ok(loopIssue, 'Deve registrar erro para /loop1 com excesso de redirects');
        assert.equal(loopIssue.severity, 'error');
      } finally {
        await srv.close();
      }
    });
  });

  describe('4. Erros 500 mascarados em HTML 200 OK', () => {
    it('4a. detecta Next.js error overlay (nextjs__container_errors / Unhandled Runtime Error) em 200 OK', async () => {
      const srv = await startHttpServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
          <html><body>
            <div class="nextjs__container_errors">
              <h1>Unhandled Runtime Error</h1>
              <p>TypeError: Cannot read properties of undefined</p>
            </div>
          </body></html>
        `);
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, false);
        assert.ok(
          res.issues.some(
            (i) => i.kind === 'masked_error' && i.severity === 'error' && i.route === '/',
          ),
        );
      } finally {
        await srv.close();
      }
    });

    it('4b. detecta Vite error overlay (<vite-error-overlay> / [plugin:vite:react-babel]) em 200 OK', async () => {
      const srv = await startHttpServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
          <html><body>
            <vite-error-overlay></vite-error-overlay>
            <pre>[plugin:vite:react-babel] Unexpected token (12:4)</pre>
          </body></html>
        `);
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, false);
        assert.ok(
          res.issues.some(
            (i) => i.kind === 'masked_error' && i.severity === 'error' && i.route === '/',
          ),
        );
      } finally {
        await srv.close();
      }
    });

    it('4c. não gera falso positivo para texto comum "Error: 0 items" nem para "statusCode": 500 fora de __NEXT_DATA__', async () => {
      const healthyHtml = `
        <html>
          <body>
            <p>Status: Error: 0 items found in filter</p>
            <pre>API docs example: { "statusCode": 500, "err": { "name": "ExampleError" } }</pre>
            <script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{}},"page":"/"}</script>
          </body>
        </html>
      `;
      const srv = await startHttpServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(healthyHtml);
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        assert.deepEqual(res.issues, []);
        assert.deepEqual(detectMaskedError(healthyHtml, '/'), []);
      } finally {
        await srv.close();
      }
    });
  });

  it('5. Vazamento de segredos no HTML e em <script src> priorizados + Redaction + Falsos Positivos', async () => {
    const requestedAssets = [];
    const rawLeakKey = ['sk', 'live', '9876543210abcdef1234'].join('_');

    const srv = await startHttpServer((req, res) => {
      const url = req.url ?? '/';
      requestedAssets.push(url);

      if (url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
          <!doctype html>
          <html>
            <head>
              <script type="module" src="/@vite/client"></script>
              <script src="/_next/static/chunks/webpack.js"></script>
            </head>
            <body>
              <form>
                <input type="password" name="password" placeholder="Enter password" />
              </form>
              <script>
                window.PUBLIC_STRIPE = "pk_live_1234567890abcdef";
                window.NEXT_PUBLIC_API_KEY = "secret_public_val";
                window.VITE_APP_SECRET = "vite_public_val";
              </script>
              <script type="module" src="/src/main.tsx"></script>
            </body>
          </html>
        `);
        return;
      }

      if (url === '/src/main.tsx') {
        res.writeHead(200, { 'Content-Type': 'application/javascript' });
        res.end(`
          import { App } from "/src/App.tsx";
          console.log(App);
        `);
        return;
      }

      if (url === '/src/App.tsx') {
        res.writeHead(200, { 'Content-Type': 'application/javascript' });
        res.end(`
          export const App = () => {
            const key = "${rawLeakKey}";
            return key;
          };
        `);
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end('// bundle');
    });

    try {
      const res = await runVibesane({ port: srv.port });
      assert.equal(res.ok, false);

      // Valida que scripts internos de runtime (@vite/client, webpack.js) foram ignorados
      assert.equal(requestedAssets.includes('/@vite/client'), false);
      assert.equal(requestedAssets.includes('/_next/static/chunks/webpack.js'), false);

      // Valida que /src/main.tsx e seu import de 1º nível /src/App.tsx foram escaneados
      assert.ok(res.scannedScripts.includes('/src/main.tsx'));
      assert.ok(res.scannedScripts.includes('/src/App.tsx'));

      // Apenas 1 issue (o sk_live_ em /src/App.tsx), sem falsos positivos para pk_live_, NEXT_PUBLIC_, VITE_ ou input password
      const secretIssues = res.issues.filter((i) => i.kind === 'secret_leak');
      assert.equal(secretIssues.length, 1);

      const leak = secretIssues[0];
      assert.equal(leak.severity, 'error');
      assert.equal(leak.route, '/src/App.tsx');
      assert.equal(leak.maskedSnippet, 'sk_live_****1234');
      assert.equal(redactSecret(rawLeakKey), 'sk_live_****1234');

      // Garante que o segredo bruto NUNCA aparece em detail, maskedSnippet ou message
      assert.equal(leak.detail.includes('9876543210abcdef'), false);
      assert.equal((leak.maskedSnippet ?? '').includes('9876543210abcdef'), false);
      assert.equal(res.message.includes('9876543210abcdef'), false);
      assert.ok(leak.detail.includes('sk_live_****1234'));

      // Valida diretamente scanSecrets contra falsos positivos
      assert.deepEqual(
        scanSecrets(
          '<input type="password" name="password"> pk_live_1234567890abcdef NEXT_PUBLIC_SECRET="abcdef123456" VITE_SECRET="abcdef123456"',
          '/',
        ),
        [],
      );
    } finally {
      await srv.close();
    }
  });

  describe('6. Rota lenta (slow_route) baseada no tempo de headers (e não de streaming do body) como warning (ok: true, exit code 0)', () => {
    it('6a. sub-rota /slow-headers que demora 120ms para enviar headers (slowRouteMs: 50) gera warning mas mantém ok: true e exit code 0', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><a href="/slow-headers">Slow Headers</a></body></html>');
          return;
        }
        if (url === '/slow-headers') {
          setTimeout(() => {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<html><body>Slow response</body></html>');
          }, 120);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port, slowRouteMs: 50 });
        assert.equal(res.ok, true);
        assert.equal(res.issues.length, 1);

        const slowIssue = res.issues[0];
        assert.equal(slowIssue.kind, 'slow_route');
        assert.equal(slowIssue.severity, 'warning');
        assert.equal(slowIssue.route, '/slow-headers');
        assert.match(slowIssue.detail, /may be dev server compilation; re-run to confirm/);
        assert.match(res.message, /warning \[slow_route\]:/);

        const cliRes = await runCli(['--port', String(srv.port)]);
        assert.equal(cliRes.code, EXIT_CODES.OK);
        assert.equal(cliRes.code, 0);
      } finally {
        await srv.close();
      }
    });

    it('6b. sub-rota /streaming-body que envia headers em ~2ms e faz streaming do body por 150ms (slowRouteMs: 60) NÃO gera slow_route', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><a href="/streaming-body">Streaming Body</a></body></html>');
          return;
        }
        if (url === '/streaming-body') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.write('<html><body>part1');
          setTimeout(() => {
            res.end(' part2</body></html>');
          }, 150);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port, slowRouteMs: 60 });
        assert.equal(res.ok, true);
        assert.deepEqual(res.issues, []);
      } finally {
        await srv.close();
      }
    });
  });

  it('7. Prazo global (scanBudgetMs), concorrência máxima (4) e resultado parcial (skippedRoutes)', async () => {
    const srv = await startHttpServer((req, res) => {
      const url = req.url ?? '/';
      if (url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
          <html><body>
            <a href="/r1">R1</a>
            <a href="/r2">R2</a>
            <a href="/r3">R3</a>
            <a href="/r4">R4</a>
            <a href="/r5">R5</a>
            <a href="/r6">R6</a>
          </body></html>
        `);
        return;
      }

      if (url === '/r1' || url === '/r2' || url === '/r3' || url === '/r4') {
        setTimeout(() => {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body>delayed</body></html>');
        }, 300);
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body>fast</body></html>');
    });

    try {
      const res = await runVibesane({
        port: srv.port,
        scanBudgetMs: 120,
      });

      assert.equal(res.ok, true);
      assert.ok(
        res.skippedRoutes.length > 0,
        `Esperava rotas em skippedRoutes, mas recebeu: ${JSON.stringify(res.skippedRoutes)}`,
      );
      assert.match(res.message, /not checked \(time budget reached\)/);
    } finally {
      await srv.close();
    }
  });

  it('8. Validação de fronteira para opções de scan (maxConcurrency, maxRoutes, maxScripts e timeouts inválidos)', async () => {
    await assert.rejects(() => runVibesane({ port: 3000, maxConcurrency: 0 }), RangeError);
    await assert.rejects(() => runVibesane({ port: 3000, maxRoutes: 0 }), RangeError);
    await assert.rejects(() => runVibesane({ port: 3000, maxScripts: -1 }), RangeError);
    await assert.rejects(() => runVibesane({ port: 3000, scanBudgetMs: -5 }), RangeError);
  });

  describe('9. Regressões Red Team (Vite Transform 500, Next 16 Turbopack, Timeout de Compilação, Senhas com Espaço e 500 Consolidado)', () => {
    it('9a. [Ajuste 1] Componente quebrado no Vite com status 500 em módulo importado falha o scan e sanitiza segredo no snippet', async () => {
      const leakedInTransform = ['sk', 'live', '99999999999999999999abcd'].join('_');
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><script type="module" src="/src/main.tsx"></script></body></html>');
          return;
        }
        if (url === '/src/main.tsx') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end('import { Pay } from "/src/components/Pay.tsx";\nconsole.log(Pay);');
          return;
        }
        if (url === '/src/components/Pay.tsx') {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end(
            `Transform failed with 1 error: /src/components/Pay.tsx:12:4: ERROR: Unexpected token (leaked ${leakedInTransform})`,
          );
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, false);

        const httpErr = res.issues.find(
          (i) => i.kind === 'http_error' && i.route === '/src/components/Pay.tsx',
        );
        assert.ok(httpErr, 'Deve emitir http_error para /src/components/Pay.tsx');
        assert.equal(httpErr.severity, 'error');
        assert.equal(httpErr.statusCode, 500);
        assert.match(httpErr.detail, /Transform failed/);
        assert.ok(httpErr.detail.includes('sk_live_****abcd'));
        assert.equal(httpErr.detail.includes('99999999999999999999'), false);
        assert.equal((httpErr.maskedSnippet ?? '').includes('99999999999999999999'), false);

        const cliRes = await runCli(['--port', String(srv.port)]);
        assert.equal(cliRes.code, EXIT_CODES.SANITY_FAILURE);
        assert.equal(cliRes.code, 1);
      } finally {
        await srv.close();
      }
    });

    it('9b. [Ajuste 2] Next 16 com Turbopack (16 scripts): exclui os 13 chunks de infraestrutura e escaneia os 3 chunks da aplicação', async () => {
      const infraScripts = [
        '/_next/static/chunks/%5Bturbopack%5D_browser_dev_hmr-client_hmr-client_ts_123456._.js',
        '/_next/static/chunks/node_modules_next_dist_compiled_react-dom_123456._.js',
        '/_next/static/chunks/node_modules_next_dist_compiled_react-server-dom-turbopack_123456._.js',
        '/_next/static/chunks/node_modules_next_dist_compiled_next-devtools_index_123456.js',
        '/_next/static/chunks/node_modules_next_dist_compiled_123456._.js',
        '/_next/static/chunks/node_modules_next_dist_client_123456._.js',
        '/_next/static/chunks/node_modules_next_dist_123456._.js',
        '/_next/static/chunks/node_modules_%40swc_helpers_cjs_123456._.js',
        '/_next/static/chunks/polyfills_123456._.js',
        '/_next/static/chunks/polyfill-nomodule.js',
        '/_next/static/chunks/turbopack-_123456._.js',
        '/_next/static/chunks/webpack-123456.js',
        '/_next/static/chunks/main-app-123456.js',
      ];
      const appScripts = [
        '/_next/static/chunks/app_layout_tsx_123456._.js',
        '/_next/static/chunks/app_page_tsx_123456._.js',
        '/_next/static/chunks/_1krgdap0boni4._.js',
      ];
      const all16 = [...infraScripts, ...appScripts];

      const selected = selectScriptsToFetch(all16, 5);
      assert.deepEqual(selected, appScripts);

      const requestedByCrawler = [];
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        requestedByCrawler.push(url);

        if (url === '/') {
          const scriptTags = all16.map((s) => `<script src="${s}"></script>`).join('\n');
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`<!doctype html><html><head>${scriptTags}</head><body>Next 16</body></html>`);
          return;
        }

        if (url === '/_next/static/chunks/_1krgdap0boni4._.js') {
          const fakeKey = ['sk', 'live', '51H8abcDEF1234567890xyz9876'].join('_');
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end(`const key = "${fakeKey}";`);
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/javascript' });
        res.end('// clean chunk');
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, false);

        for (const infra of infraScripts) {
          assert.equal(
            requestedByCrawler.includes(infra),
            false,
            `Infra script deveria ser ignorado: ${infra}`,
          );
        }
        for (const appChunk of appScripts) {
          assert.ok(
            res.scannedScripts.includes(appChunk),
            `App chunk deveria ser escaneado: ${appChunk}`,
          );
        }

        const leak = res.issues.find(
          (i) =>
            i.kind === 'secret_leak' && i.route === '/_next/static/chunks/_1krgdap0boni4._.js',
        );
        assert.ok(leak, 'Deve detectar secret_leak no chunk _1krgdap0boni4._.js');
        assert.equal(leak.maskedSnippet, 'sk_live_****9876');
        assert.equal(leak.detail.includes('51H8abcDEF1234567890xyz'), false);
      } finally {
        await srv.close();
      }
    });

    it('9c. [Ajuste 3] Sub-rota que estoura routeTimeoutMs vira slow_route warning (ok: true), mas falha real de socket gera http_error (ok: false)', async () => {
      const compilingSrv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><a href="/compiling-page">Compiling</a></body></html>');
          return;
        }
        if (url === '/compiling-page') {
          setTimeout(() => {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<html><body>Compiled</body></html>');
          }, 300);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({
          port: compilingSrv.port,
          routeTimeoutMs: 100,
          scanBudgetMs: 2000,
        });
        assert.equal(res.ok, true);
        assert.ok(res.routes.some((r) => r.path === '/compiling-page'));

        const slowWarning = res.issues.find((i) => i.route === '/compiling-page');
        assert.ok(slowWarning, 'Deve emitir issue para /compiling-page');
        assert.equal(slowWarning.kind, 'slow_route');
        assert.equal(slowWarning.severity, 'warning');
        assert.match(slowWarning.detail, /did not respond within 100ms/);
        assert.match(slowWarning.detail, /may be dev server compilation/);
      } finally {
        await compilingSrv.close();
      }

      const brokenSrv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><a href="/broken-socket">Broken</a></body></html>');
          return;
        }
        if (url === '/broken-socket') {
          req.socket.destroy();
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const resBroken = await runVibesane({ port: brokenSrv.port });
        assert.equal(resBroken.ok, false);
        const connErr = resBroken.issues.find(
          (i) => i.route === '/broken-socket' && i.kind === 'http_error',
        );
        assert.ok(connErr, 'Deve emitir http_error para falha de conexão real');
        assert.equal(connErr.severity, 'error');

        const cliRes = await runCli(['--port', String(brokenSrv.port)]);
        assert.equal(cliRes.code, EXIT_CODES.SANITY_FAILURE);
        assert.equal(cliRes.code, 1);
      } finally {
        await brokenSrv.close();
      }
    });

    it('9d. [Ajuste 4] Mensagens de validação de senha com espaços são ignoradas, mas senhas reais sem espaço são detectadas', async () => {
      const uiValidationPayload = `
        const messages = {
          password: "Password must be at least 8 characters",
          senha: "Digite sua senha"
        };
      `;
      assert.deepEqual(scanSecrets(uiValidationPayload, '/src/login.tsx'), []);

      const realHardcodedPayload = `
        const credentials = {
          password: "SuperSecret123!"
        };
      `;
      const detected = scanSecrets(realHardcodedPayload, '/src/login.tsx');
      assert.equal(detected.length, 1);
      assert.equal(detected[0].kind, 'secret_leak');
      assert.equal(detected[0].severity, 'error');
      assert.equal(detected[0].detail.includes('SuperSecret123!'), false);
    });

    it('9e. [Ajuste 5] Página 500 com marcador de erro mascarado gera apenas 1 http_error consolidado (sem duplicar masked_error)', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><a href="/crash500">Crash 500</a></body></html>');
          return;
        }
        if (url === '/crash500') {
          res.writeHead(500, { 'Content-Type': 'text/html' });
          res.end(
            '<html><head><title>500 Internal Server Error</title></head><body>Unhandled Runtime Error</body></html>',
          );
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, false);

        const crashIssues = res.issues.filter((i) => i.route === '/crash500');
        assert.equal(
          crashIssues.length,
          1,
          `Esperava exatamente 1 issue consolidado para /crash500, mas recebeu: ${JSON.stringify(crashIssues)}`,
        );
        assert.equal(crashIssues[0].kind, 'http_error');
        assert.equal(crashIssues[0].severity, 'error');
        assert.equal(crashIssues[0].statusCode, 500);
        assert.match(
          crashIssues[0].detail,
          /Unhandled Runtime Error|HTML 500 \/ Internal Server Error heading/,
        );
      } finally {
        await srv.close();
      }
    });

    it('10a. Fixture real capturada do Next 14.2 (app/layout.js do Portal com @supabase/auth-js): zero falsos positivos de senha (0 issues)', () => {
      const fixtureUrl = new URL('./fixtures/next14-portal-layout-chunk.js', import.meta.url);
      const chunk = readFileSync(fixtureUrl, 'utf8');

      const issues = scanSecrets(chunk, '/_next/static/chunks/app/layout.js');
      assert.equal(
        issues.length,
        0,
        `Esperava 0 issues para o layout real com Supabase, mas recebeu: ${JSON.stringify(issues)}`,
      );
    });

    it('10b. Fixture real do Next 16 webpack com Supabase: descarta exemplos JSDoc do auth-js mas detecta senha real em Checkout.tsx DEPOIS do import do Supabase', () => {
      const fixtureUrl = new URL('./fixtures/next16-webpack-supabase-chunk.js', import.meta.url);
      const chunk = readFileSync(fixtureUrl, 'utf8');

      const issues = scanSecrets(chunk, '/_next/static/chunks/app/page.js');
      assert.equal(
        issues.length,
        1,
        `Esperava exatamente 1 issue (senha real no Checkout), mas recebeu: ${JSON.stringify(issues)}`,
      );
      assert.equal(issues[0].kind, 'secret_leak');
      assert.equal(issues[0].severity, 'error');
      assert.equal(issues[0].route, 'src/app/components/Checkout.tsx');
      assert.match(issues[0].detail, /Hardcoded password \(M\*\*\*\)/);
      assert.equal(issues[0].detail.includes('MinhaSenhaReal123'), false);
    });

    it('10c. Next 16 webpack: senha real em módulo ./src/... ANTES do módulo do Supabase continua detectada e atribuída a src/...', () => {
      const chunkBefore = [
        '(self["webpackChunk_N_E"] = self["webpackChunk_N_E"] || []).push([["app/page"],{',
        '/***/ "(app-pages-browser)/./src/app/components/Sidebar.tsx":',
        '/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {',
        '  const creds = { password: "SenhaAntesDoSupabase123" };',
        '}),',
        '/***/ "(app-pages-browser)/./node_modules/@supabase/auth-js/dist/module/GoTrueClient.js":',
        '/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {',
        '  // JSDoc example: password: "some-password"',
        '}),',
        '}]);',
      ].join('\n');

      const issues = scanSecrets(chunkBefore, '/_next/static/chunks/app/page.js');
      assert.equal(issues.length, 1);
      assert.equal(issues[0].route, 'src/app/components/Sidebar.tsx');
      assert.match(issues[0].detail, /Hardcoded password \(S\*\*\*\)/);
      assert.equal(issues[0].detail.includes('SenhaAntesDoSupabase123'), false);
    });

    it('10d. Chave token de alta entropia (sk_live_) dentro de módulo node_modules continua sendo detectada e atribuída à rota do chunk', () => {
      const fakeStripe = ['sk', 'live', '112233445566778899aabbcc'].join('_');
      const chunkVendorSecret = [
        '(self["webpackChunk_N_E"] = self["webpackChunk_N_E"] || []).push([["app/page"],{',
        '/***/ "(app-pages-browser)/./node_modules/compromised-lib/index.js":',
        '/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {',
        `  const stripeKey = "${fakeStripe}";`,
        '}),',
        '}]);',
      ].join('\n');

      const issues = scanSecrets(chunkVendorSecret, '/_next/static/chunks/app/page.js');
      assert.equal(issues.length, 1);
      assert.equal(issues[0].kind, 'secret_leak');
      assert.equal(issues[0].route, '/_next/static/chunks/app/page.js');
      assert.ok(issues[0].detail.includes('sk_live_****bbcc'));
      assert.equal(issues[0].detail.includes('112233445566778899'), false);
    });

    it('10e. Fixture Turbopack Next 16 com sufixo <locals> e <export default as AuthClient>: descarta exemplos de terceiros e detecta senha real em Checkout.tsx', () => {
      const fixtureUrl = new URL('./fixtures/next16-turbopack-supabase-chunk.js', import.meta.url);
      const chunk = readFileSync(fixtureUrl, 'utf8');

      const issues = scanSecrets(chunk, '/_next/static/chunks/app/page.js');
      assert.equal(
        issues.length,
        1,
        `Esperava exatamente 1 issue no Turbopack (Checkout.tsx), mas recebeu: ${JSON.stringify(issues)}`,
      );
      assert.equal(issues[0].kind, 'secret_leak');
      assert.equal(issues[0].route, 'src/app/components/Checkout.tsx');
      assert.match(issues[0].detail, /Hardcoded password \(M\*\*\*\)/);
      assert.equal(issues[0].detail.includes('MinhaSenhaReal123'), false);
    });

    it('10f. Monorepo webpack (../packages/ui/src/Button.tsx): reconhece caminhos subindo diretório como módulo da aplicação', () => {
      const monorepoChunk = [
        '(self["webpackChunk_N_E"] = self["webpackChunk_N_E"] || []).push([["app/page"],{',
        '/***/ "(app-pages-browser)/../packages/ui/src/Button.tsx":',
        '/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {',
        '  const creds = { password: "MonorepoSecret123" };',
        '}),',
        '}]);',
      ].join('\n');

      const issues = scanSecrets(monorepoChunk, '/_next/static/chunks/app/page.js');
      assert.equal(issues.length, 1);
      assert.equal(issues[0].kind, 'secret_leak');
      assert.equal(issues[0].route, 'packages/ui/src/Button.tsx');
      assert.match(issues[0].detail, /Hardcoded password \(M\*\*\*\)/);
      assert.equal(issues[0].detail.includes('MonorepoSecret123'), false);
    });
  });

  describe('11. Chunks grandes do Webpack (> 1MB até 8MB) e avisos de corte transparente (truncated_body)', () => {
    it('11a. Chunk do Webpack de 2.8 MB com node_modules primeiro e código do usuário aos 2.8 MB é varrido por completo e detecta segredo', async () => {
      const fakeStripe = ['sk', 'live', '998877665544332211aabbcc'].join('_');
      // Constrói ~2.7 MB de módulos node_modules no início
      const chunkVendorPadding = '/***/ "(app-pages-browser)/./node_modules/huge-pkg/index.js":\n/***/ (function() { return 1; }),\n'.repeat(30000); // ~2.7 MB
      const userComponent = [
        '/***/ "(app-pages-browser)/./src/app/Checkout.tsx":',
        '/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {',
        `  const stripeKey = "${fakeStripe}";`,
        '}),',
      ].join('\n');
      const fullChunk = `(self["webpackChunk_N_E"] = self["webpackChunk_N_E"] || []).push([["app/page"],{\n${chunkVendorPadding}\n${userComponent}\n}]);`;

      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<!DOCTYPE html><html><body><script src="/_next/static/chunks/app/page.js"></script></body></html>');
          return;
        }
        if (url === '/_next/static/chunks/app/page.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end(fullChunk);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, false);
        const secretIssues = res.issues.filter((i) => i.kind === 'secret_leak');
        assert.equal(secretIssues.length, 1);
        assert.equal(secretIssues[0].route, 'src/app/Checkout.tsx');
        assert.ok(secretIssues[0].detail.includes('sk_live_****bbcc'));
        assert.equal(res.issues.some((i) => i.kind === 'truncated_body'), false);
      } finally {
        await srv.close();
      }
    });

    it('11b. Página HTML que excede 1 MB (1.5 MB) é cortada nos 1024 KB e emite warning [truncated_body] (exceeded 1 MB limit) mantendo ok: true', async () => {
      const largeHtml = '<!DOCTYPE html><html><body>' + '<div>Safe content</div>\n'.repeat(70000) + '</body></html>'; // ~1.6 MB

      const srv = await startHttpServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(largeHtml);
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        const truncIssues = res.issues.filter((i) => i.kind === 'truncated_body');
        assert.equal(truncIssues.length, 1);
        assert.equal(truncIssues[0].severity, 'warning');
        assert.equal(truncIssues[0].route, '/');
        assert.equal(truncIssues[0].detail, 'response body truncated on / (exceeded 1 MB limit)');
        assert.ok(res.message.includes('warning [truncated_body]: response body truncated on / (exceeded 1 MB limit)'));
      } finally {
        await srv.close();
      }
    });

    it('11c. Script que excede 8 MB (~9 MB) é cortado nos 8 MB e emite warning [truncated_body] (exceeded 8 MB limit)', async () => {
      const hugeScript = '/* harmless */ function f() { return 1; }\n'.repeat(210000); // ~9 MB

      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<!DOCTYPE html><html><body><script src="/_next/static/chunks/app/page.js"></script></body></html>');
          return;
        }
        if (url === '/_next/static/chunks/app/page.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end(hugeScript);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        const truncIssues = res.issues.filter((i) => i.kind === 'truncated_body');
        assert.equal(truncIssues.length, 1);
        assert.equal(truncIssues[0].severity, 'warning');
        assert.equal(truncIssues[0].route, '/_next/static/chunks/app/page.js');
        assert.equal(
          truncIssues[0].detail,
          'response body truncated on script /_next/static/chunks/app/page.js (exceeded 8 MB limit)',
        );
      } finally {
        await srv.close();
      }
    });

    it('11d. Script cujo stream sofre timeout de leitura (> 1000 ms) emite warning [truncated_body] (read timeout after 1000 ms)', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<!DOCTYPE html><html><body><script src="/_next/static/chunks/app/page.js"></script></body></html>');
          return;
        }
        if (url === '/_next/static/chunks/app/page.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.write('/* header part */');
          // Demora mais que DEFAULT_SCRIPT_BODY_READ_TIMEOUT_MS (1000ms), ex: 1200ms
          setTimeout(() => {
            res.end('/* slow trailing part */');
          }, 1200);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        const truncIssues = res.issues.filter((i) => i.kind === 'truncated_body');
        assert.equal(truncIssues.length, 1);
        assert.equal(truncIssues[0].severity, 'warning');
        assert.equal(truncIssues[0].route, '/_next/static/chunks/app/page.js');
        assert.equal(
          truncIssues[0].detail,
          'response body truncated on script /_next/static/chunks/app/page.js (read timeout after 1000 ms)',
        );
      } finally {
        await srv.close();
      }
    });

    it('11e. Script com erro de stream de rede emite warning [truncated_body] (stream error)', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<!DOCTYPE html><html><body><script src="/_next/static/chunks/app/page.js"></script></body></html>');
          return;
        }
        if (url === '/_next/static/chunks/app/page.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.write('/* initial part */');
          setTimeout(() => {
            res.destroy();
          }, 50);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        // Com stream destruído no meio da leitura do body, deve registrar truncated_body (stream error)
        const truncIssues = res.issues.filter((i) => i.kind === 'truncated_body');
        assert.ok(truncIssues.length >= 1);
        assert.equal(truncIssues[0].detail, 'response body truncated on script /_next/static/chunks/app/page.js (stream error)');
      } finally {
        await srv.close();
      }
    });
  });

  describe('12. Linha de Cobertura e Diagnostico de Servidor Frio (v0.1.3)', () => {
    it('12a. Cenário OK com páginas e scripts inspecionados (info: checked 1 page, 2 scripts)', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <html>
              <head>
                <script src="/src/main.js"></script>
                <script src="/src/vendor.js"></script>
              </head>
              <body><h1>Clean App</h1></body>
            </html>
          `);
          return;
        }
        if (url === '/src/main.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end('console.log("main");');
          return;
        }
        if (url === '/src/vendor.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end('console.log("vendor");');
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        assert.equal(res.issues.length, 0);
        assert.ok(
          res.message.includes('info: checked 1 page, 2 scripts'),
          `Esperava linha de cobertura na mensagem:\n${res.message}`,
        );
        const lines = res.message.split('\n');
        assert.ok(lines[0].startsWith('vibesane: connected to http://localhost:'));
        assert.equal(lines[1], 'info: checked 1 page, 2 scripts');
      } finally {
        await srv.close();
      }
    });

    it('12b. Pluralidade correta (2 pages, 1 script)', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <html>
              <head><script src="/src/app.js"></script></head>
              <body><a href="/about">About</a></body>
            </html>
          `);
          return;
        }
        if (url === '/about') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body>About page</body></html>');
          return;
        }
        if (url === '/src/app.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end('console.log("app");');
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        assert.ok(res.message.includes('info: checked 2 pages, 1 script'));
      } finally {
        await srv.close();
      }
    });

    it('12c. Cenário de falha (ok: false): linha de cobertura aparece depois dos erros error [...]', async () => {
      const fakeStripeKey = ['sk', 'live', '11223344556677889900abcd'].join('_');
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <html>
              <head><script src="/src/broken.js"></script></head>
              <body><h1>Broken</h1></body>
            </html>
          `);
          return;
        }
        if (url === '/src/broken.js') {
          res.writeHead(500, { 'Content-Type': 'application/javascript' });
          res.end(`const key = "${fakeStripeKey}"; throw new Error("crash");`);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, false);
        const lines = res.message.split('\n');
        const errIndex = lines.findIndex((l) => l.startsWith('error ['));
        const coverageIndex = lines.findIndex((l) => l.startsWith('info: checked '));
        assert.ok(errIndex !== -1, 'Deve conter linha error [...]');
        assert.ok(coverageIndex !== -1, 'Deve conter linha info: checked ...');
        assert.ok(coverageIndex > errIndex, 'Linha de cobertura deve vir apos as linhas de erro');
        assert.equal(lines[coverageIndex], 'info: checked 1 page, 1 script');
      } finally {
        await srv.close();
      }
    });

    it('12d. Raiz 200 sem scripts: info: checked 1 page, 0 scripts (não aciona nothing was checked)', async () => {
      const srv = await startHttpServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body>Static HTML without scripts</body></html>');
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        assert.ok(res.message.includes('info: checked 1 page, 0 scripts'));
        assert.equal(res.message.includes('nothing was checked'), false);
      } finally {
        await srv.close();
      }
    });

    it('12e. Redirect 307 com destino lento estourando routeTimeoutMs: slow route / -> /login (omite query string) + info: nothing was checked (/ did not respond in time) + ok: true', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(307, {
            Location: '/login?token=super-secret-param&next=/dashboard',
          });
          res.end();
          return;
        }
        if (url.startsWith('/login')) {
          // Segura a resposta além do routeTimeoutMs (100ms)
          setTimeout(() => {
            if (!res.writableEnded) {
              res.writeHead(200, { 'Content-Type': 'text/html' });
              res.end('<html><body>Login</body></html>');
            }
          }, 300);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({
          port: srv.port,
          routeTimeoutMs: 100,
        });

        // Lentidão de compilação em dev server não falha a sanidade: ok: true
        assert.equal(res.ok, true);
        const slowIssue = res.issues.find((i) => i.kind === 'slow_route' && i.route === '/');
        assert.ok(slowIssue, 'Deve registrar slow_route na raiz');
        assert.ok(
          slowIssue.detail.includes('slow route / -> /login (did not respond within 100ms'),
          `Mensagem esperada com /login:\n${slowIssue.detail}`,
        );
        // Não deve expor a query string (?token=...)
        assert.equal(slowIssue.detail.includes('token='), false);
        assert.equal(slowIssue.detail.includes('super-secret-param'), false);

        assert.ok(
          res.message.includes(
            'info: nothing was checked (/ did not respond in time); re-run after the dev server finishes compiling',
          ),
          `Mensagem inesperada:\n${res.message}`,
        );
      } finally {
        await srv.close();
      }
    });

    it('12f. Redirect 307 para fora do servidor local (https://example.com/login): info: nothing was checked (/ redirects outside the local server) sem slow_route + ok: true', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(307, {
            Location: 'https://example.com/login?partner=corp',
          });
          res.end();
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        assert.equal(res.issues.some((i) => i.kind === 'slow_route'), false);
        assert.ok(
          res.message.includes(
            'info: nothing was checked (/ redirects outside the local server)',
          ),
          `Mensagem inesperada:\n${res.message}`,
        );
      } finally {
        await srv.close();
      }
    });

    it('12g. Redirect 307 sem header Location: info: nothing was checked + ok: true', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(307);
          res.end();
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        const lines = res.message.split('\n');
        assert.equal(lines[1], 'info: nothing was checked');
      } finally {
        await srv.close();
      }
    });

    it('12h. Sub-rota que termina em status 3xx externo não conta como página inspecionada (contagem uniforme)', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <html>
              <body>
                <a href="/external-redirect">Auth SSO</a>
                <a href="/internal-page">Dashboard</a>
              </body>
            </html>
          `);
          return;
        }
        if (url === '/external-redirect') {
          res.writeHead(302, { Location: 'https://auth0.example.com/authorize' });
          res.end();
          return;
        }
        if (url === '/internal-page') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body>Dashboard OK</body></html>');
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        // / conta (200), /internal-page conta (200), /external-redirect não conta (302) -> exatamente 2 pages
        assert.ok(
          res.message.includes('info: checked 2 pages, 0 scripts'),
          `Mensagem esperava 2 pages, obteve:\n${res.message}`,
        );
      } finally {
        await srv.close();
      }
    });

    it('12i. terminal-ui e NO_COLOR: formato ASCII limpo, info sem cor própria e primeira linha colorida com TTY', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/app.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end('console.log("app loaded");');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><head><script src="/app.js"></script></head><body>OK</body></html>');
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);

        // 1. Sem cor (NO_COLOR ou color: false)
        const plainReport = formatTerminalReport(res, { color: false });
        assert.equal(plainReport.includes('\x1b['), false);
        assert.ok(plainReport.includes('info: checked 1 page, 1 script'));

        // 2. Com cor ativa (color: true, FORCE_COLOR: '1')
        const prevForceColor = process.env.FORCE_COLOR;
        process.env.FORCE_COLOR = '1';
        try {
          const coloredReport = formatTerminalReport(res, {
            color: true,
            isTTY: true,
            env: { FORCE_COLOR: '1' },
          });
          const lines = coloredReport.split('\n');
          // Primeira linha verde
          assert.ok(lines[0].startsWith('\x1b[32mvibesane: connected to'));
          // Linha info: checked sem cor própria
          assert.equal(lines[1], 'info: checked 1 page, 1 script');
          assert.equal(lines[1].includes('\x1b['), false);
        } finally {
          if (prevForceColor === undefined) {
            delete process.env.FORCE_COLOR;
          } else {
            process.env.FORCE_COLOR = prevForceColor;
          }
        }
      } finally {
        await srv.close();
      }
    });

    it('12j. Next 16 redirect 307 com corpo RSC contendo NEXT_REDIRECT não aciona falso positivo de masked_error e mantém código 0', async () => {
      const next16RedirectRscBody = `
        <!DOCTYPE html>
        <html>
          <head><meta charset="utf-8"/></head>
          <body>
            <script>
              self.__next_f.push([1,"1:{\\"type\\":\\"page\\",\\"pagePath\\":\\"src/app/page.tsx\\"}\\n2:{\\"name\\":\\"Error\\",\\"message\\":\\"NEXT_REDIRECT;replace;/login?next=/dashboard;307;\\"}\\n"]);
            </script>
          </body>
        </html>
      `;

      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(307, {
            'Content-Type': 'text/html; charset=utf-8',
            Location: '/login?next=/dashboard',
          });
          res.end(next16RedirectRscBody);
          return;
        }
        if (url.startsWith('/login')) {
          // Segura a resposta simulando compilação lenta do dev server
          setTimeout(() => {
            if (!res.writableEnded) {
              res.writeHead(200, { 'Content-Type': 'text/html' });
              res.end('<html><body>Login Page</body></html>');
            }
          }, 300);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({
          port: srv.port,
          routeTimeoutMs: 100,
        });

        // Não pode acusar masked_error falso-positivo em 307!
        assert.equal(res.ok, true, 'ok deve ser true mesmo com NEXT_REDIRECT no corpo 307');
        const maskedIssues = res.issues.filter((i) => i.kind === 'masked_error');
        assert.equal(maskedIssues.length, 0, 'Zero masked_error em 307 de redirect');

        // Deve conter slow_route com destino limpo
        const slowIssue = res.issues.find((i) => i.kind === 'slow_route' && i.route === '/');
        assert.ok(slowIssue);
        assert.ok(slowIssue.detail.includes('slow route / -> /login'));
        assert.equal(slowIssue.detail.includes('?next='), false);

        // Mensagem deve orientar re-execução sem erros
        assert.ok(
          res.message.includes(
            'info: nothing was checked (/ did not respond in time); re-run after the dev server finishes compiling',
          ),
        );
      } finally {
        await srv.close();
      }
    });

    it('12k. Teste negativo: erro 500 com overlay e runtime error continua sendo reportado como erro de sanidade', async () => {
      const next16Real500 = `
        <!DOCTYPE html>
        <html>
          <head><title>500 Internal Error</title></head>
          <body>
            <script>
              self.__next_f.push([1,"1:{\\"type\\":\\"page\\",\\"pagePath\\":\\"src/app/page.tsx\\"}\\n2:{\\"name\\":\\"TypeError\\",\\"message\\":\\"Cannot read properties of undefined (reading 'auth')\\"}\\n"]);
            </script>
          </body>
        </html>
      `;

      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(500, {
            'Content-Type': 'text/html; charset=utf-8',
          });
          res.end(next16Real500);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, false);
        const httpError = res.issues.find((i) => i.kind === 'http_error');
        assert.ok(httpError);
        assert.ok(httpError.detail.includes("Cannot read properties of undefined (reading 'auth')"));
      } finally {
        await srv.close();
      }
    });
  });

  describe('13. Extração de Chunks RSC Flight em Páginas Dinâmicas do Next 16 (v0.1.4)', () => {
    it('13a. Fixture real capturada do Next 16.4.5 (webpack) com página dinâmica (await connection()): extrai chunk do payload RSC e detecta segredo em Checkout.tsx', async () => {
      const htmlUrl = new URL('./fixtures/next16-webpack-dynamic-page.html', import.meta.url);
      const chunkUrl = new URL('./fixtures/next16-webpack-dynamic-chunk.js', import.meta.url);
      const dynamicHtml = readFileSync(htmlUrl, 'utf8');
      const dynamicChunkRaw = readFileSync(chunkUrl, 'utf8');

      // Monta a chave falsa sem sk_live_ literal para evitar bloqueio pelo detector de segredos do GitHub
      const fakeStripeKey = ['sk', 'live', '51Habcdefghijklmnop1234'].join('_');
      const dynamicChunk = dynamicChunkRaw.replace('__VIBESANE_TEST_STRIPE_KEY__', fakeStripeKey);

      let chunkRequests = 0;
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(dynamicHtml);
          return;
        }
        if (url === '/_next/static/chunks/app/page.js') {
          chunkRequests += 1;
          res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
          res.end(dynamicChunk);
          return;
        }
        if (url === '/_next/static/chunks/app-pages-internals.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
          res.end('/* next app-pages-internals */');
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        // Deve falhar o scan por causa da chave vazada no componente Checkout
        assert.equal(res.ok, false);
        assert.equal(chunkRequests, 1, 'Chunk app/page.js deve ser baixado exatamente uma vez');

        const secretIssues = res.issues.filter((i) => i.kind === 'secret_leak');
        assert.equal(secretIssues.length, 1);
        assert.equal(secretIssues[0].severity, 'error');
        assert.equal(secretIssues[0].route, 'src/app/components/Checkout.tsx');
        assert.ok(
          secretIssues[0].detail.includes('sk_live_****1234'),
          `Esperava detalhe com segredo mascarado, obteve: ${secretIssues[0].detail}`,
        );

        // A linha de cobertura deve reportar 1 página e 2 scripts inspecionados (app/page.js e app-pages-internals.js)
        assert.ok(
          res.message.includes('info: checked 1 page, 2 scripts'),
          `Esperava linha de cobertura com 1 page, 2 scripts:\n${res.message}`,
        );
      } finally {
        await srv.close();
      }
    });

    it('13b. Route groups e segmentos dinâmicos codificados: extrai chunks app/(shop)/cart/page.js e app/blog/%5Bslug%5D/page.js', () => {
      const flightHtml = `
        <!DOCTYPE html>
        <html>
          <body>
            <script>
              self.__next_f.push([1,"80:\\"static/chunks/app/(shop)/cart/page.js\\"\\n81:\\"static/chunks/app/blog/%5Bslug%5D/page.js\\"\\n82:\\"/_next/static/chunks/app/(dashboard)/settings/page.js\\"\\n"]);
            </script>
          </body>
        </html>
      `;

      const scripts = selectScriptsToFetch(flightHtml, 'http://localhost:3000', 10);
      assert.deepEqual(scripts, [
        '/_next/static/chunks/app/(shop)/cart/page.js',
        '/_next/static/chunks/app/blog/%5Bslug%5D/page.js',
        '/_next/static/chunks/app/(dashboard)/settings/page.js',
      ]);
    });

    it('13c. Deduplicação uniforme pelo caminho normalizado: static/chunks/x.js, /_next/static/chunks/x.js e <script src> geram 1 requisição e ocupam 1 vaga', async () => {
      // Página estática onde o chunk vem tanto em <script src> quanto em static/chunks/ e /_next/static/chunks/ no payload
      const htmlDuplicate = `
        <!DOCTYPE html>
        <html>
          <head>
            <script src="/_next/static/chunks/app/page.js"></script>
          </head>
          <body>
            <script>
              self.__next_f.push([1,"80:\\"static/chunks/app/page.js\\"\\n81:\\"/_next/static/chunks/app/page.js\\"\\n82:\\"static/chunks/app/page.js\\"\\n"]);
            </script>
          </body>
        </html>
      `;

      // 1. Verificação pura do extrator
      const candidates = selectScriptsToFetch(htmlDuplicate, 'http://localhost:3000', 5);
      assert.deepEqual(candidates, ['/_next/static/chunks/app/page.js']);

      // 2. Verificação de rede em execução real
      let fetchCount = 0;
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(htmlDuplicate);
          return;
        }
        if (url === '/_next/static/chunks/app/page.js') {
          fetchCount += 1;
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end('console.log("clean chunk");');
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        assert.equal(fetchCount, 1, 'Chunk deduplicado deve receber exatamente 1 requisição GET');
        assert.ok(res.message.includes('info: checked 1 page, 1 script'));
      } finally {
        await srv.close();
      }
    });

    it('13d. Prioridade sob limite maxScripts (teto de 5): chunks da aplicação app/... (prioridade 1) ganham de genéricos (prioridade 2)', () => {
      const htmlOverLimit = `
        <!DOCTYPE html>
        <html>
          <body>
            <script>
              self.__next_f.push([1,"80:\\"static/chunks/vendor-a.js\\"\\n81:\\"static/chunks/vendor-b.js\\"\\n82:\\"static/chunks/vendor-c.js\\"\\n83:\\"static/chunks/app/page.js\\"\\n84:\\"static/chunks/app/header.js\\"\\n85:\\"static/chunks/app/footer.js\\"\\n"]);
            </script>
          </body>
        </html>
      `;

      // maxScripts: 5 -> Temos 3 chunks app/... (prioridade 1) e 3 chunks vendor (prioridade 2)
      // Os 3 app/... DEVEM ser escolhidos, seguidos pelos 2 primeiros vendor (total 5)
      const selected = selectScriptsToFetch(htmlOverLimit, 'http://localhost:3000', 5);
      assert.equal(selected.length, 5);

      // Prioridade 1 vêm primeiro
      assert.equal(selected[0], '/_next/static/chunks/app/page.js');
      assert.equal(selected[1], '/_next/static/chunks/app/header.js');
      assert.equal(selected[2], '/_next/static/chunks/app/footer.js');
      // Prioridade 2 vêm em seguida
      assert.equal(selected[3], '/_next/static/chunks/vendor-a.js');
      assert.equal(selected[4], '/_next/static/chunks/vendor-b.js');
      assert.equal(selected.includes('/_next/static/chunks/vendor-c.js'), false, '6º chunk deve ser descartado pelo teto de 5');
    });

    it('13e. Casos negativos: URLs externas (https://, //) e texto fora de string não são agendados', () => {
      const htmlNegatives = `
        <!DOCTYPE html>
        <html>
          <body>
            <!-- URLs externas sob static/chunks nunca devem ser agendadas -->
            <a href="https://cdn.example.com/static/chunks/app/page.js">External CDN</a>
            <img src="//cdn.other.com/static/chunks/app/page.js"/>
            
            <!-- Texto fora de aspas não deve ser casado -->
            <p>Consulte static/chunks/app/page.js em nossa documentação técnica.</p>

            <!-- Referências de módulo Webpack sem ser chunk static/chunks -->
            <script>
              self.__next_f.push([1,"80:\\"(app-pages-browser)/./src/app/components/Checkout.tsx\\"\\n81:I[\\"$80\\",[\\"app/page\\",\\"$81\\"],\\"default\\"]\\n"]);
            </script>
          </body>
        </html>
      `;

      const selected = selectScriptsToFetch(htmlNegatives, 'http://localhost:3000', 5);
      assert.deepEqual(selected, [], 'Nenhum script deve ser extraído dos casos negativos');
    });

    it('13f. Turbopack: comportamento idêntico à main sem duplicar requisições', async () => {
      // No Turbopack o chunk já vem em <script src> e também no flight payload
      const turbopackHtml = `
        <!DOCTYPE html>
        <html>
          <head>
            <script src="/_next/static/chunks/app/page.js"></script>
          </head>
          <body>
            <script>
              self.__next_f.push([1,"80:\\"static/chunks/app/page.js\\"\\n"]);
            </script>
          </body>
        </html>
      `;

      let reqCount = 0;
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(turbopackHtml);
          return;
        }
        if (url === '/_next/static/chunks/app/page.js') {
          reqCount += 1;
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end('console.log("turbopack");');
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const res = await runVibesane({ port: srv.port });
        assert.equal(res.ok, true);
        assert.equal(reqCount, 1);
        assert.ok(res.message.includes('info: checked 1 page, 1 script'));
      } finally {
        await srv.close();
      }
    });
  });
});
