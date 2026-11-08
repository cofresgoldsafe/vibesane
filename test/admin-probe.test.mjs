import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  normalizeHtmlForComparison,
  looksLikeLoginPage,
  isSameAsFallback,
  maskOwnPath,
  ADMIN_PROBE_PATHS,
  probeAdminRoutes,
} from '../dist/scanner/admin-probe.js';
import { main } from '../dist/cli.js';
import { runVibesane } from '../dist/index.js';

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
        close: () =>
          new Promise((res) => {
            server.closeAllConnections?.();
            server.close(res);
          }),
      });
    });
  });
}

test('unit: normalizeHtmlForComparison handles double quotes, single quotes, and unquoted nonces and collapses whitespace', () => {
  // 1. Aspas duplas
  const h1 = '<html><head><script nonce="abc123xyz">console.log(1);</script></head><body>  Hello   World  \n\t</body></html>';
  assert.equal(
    normalizeHtmlForComparison(h1),
    '<html><head><script>console.log(1);</script></head><body> Hello World </body></html>',
  );

  // 2. Aspas simples
  const h2 = "<html><head><script nonce='abc123xyz'>console.log(1);</script></head><body> Hello World </body></html>";
  assert.equal(
    normalizeHtmlForComparison(h2),
    '<html><head><script>console.log(1);</script></head><body> Hello World </body></html>',
  );

  // 3. Sem aspas
  const h3 = '<html><head><script nonce=abc123xyz>console.log(1);</script></head><body> Hello World </body></html>';
  assert.equal(
    normalizeHtmlForComparison(h3),
    '<html><head><script>console.log(1);</script></head><body> Hello World </body></html>',
  );

  // 4. Dois HTMLs com nonces dinâmicos diferentes e formatação distinta são idênticos após normalização
  const dynamic1 = '<script nonce="dyn_aaa_111">app()</script>\n  <div>Content</div>';
  const dynamic2 = "  <script nonce='dyn_bbb_222'>app()</script>   <div>Content</div> ";
  assert.equal(
    normalizeHtmlForComparison(dynamic1),
    normalizeHtmlForComparison(dynamic2),
  );

  // 5. Vazio ou nulo
  assert.equal(normalizeHtmlForComparison(''), '');
});

test('unit: looksLikeLoginPage detects password inputs in various formats', () => {
  // Aspas duplas
  assert.equal(looksLikeLoginPage('<form><input type="password" name="pwd"></form>'), true);
  // Aspas simples
  assert.equal(looksLikeLoginPage("<form><input type='password' name='pwd'></form>"), true);
  // Sem aspas
  assert.equal(looksLikeLoginPage('<form><input type=password name=pwd></form>'), true);
  // Maiúsculas
  assert.equal(looksLikeLoginPage('<FORM><INPUT TYPE="PASSWORD"></FORM>'), true);
  // Com outros atributos antes e depois
  assert.equal(looksLikeLoginPage('<input class="form-control" name="pass" type="password" id="pass" />'), true);
  // Com quebras de linha e espaços no atributo
  assert.equal(looksLikeLoginPage('<input \n  type = "password" \n />'), true);

  // Não é login (texto, email, sem password)
  assert.equal(looksLikeLoginPage('<form><input type="text" name="user"></form>'), false);
  assert.equal(looksLikeLoginPage('<input type="email" name="email">'), false);
  assert.equal(looksLikeLoginPage('<h1>Admin Panel</h1><p>No password field</p>'), false);
  assert.equal(looksLikeLoginPage(''), false);
});

test('unit: isSameAsFallback compares normalized bodies and ignores empty references', () => {
  const candidate = '<div>  Hello  World </div>';
  const matchingFallback = '<div> Hello World </div>';
  const otherFallback = '<div> Different </div>';

  assert.equal(isSameAsFallback(candidate, [matchingFallback]), true);
  assert.equal(isSameAsFallback(candidate, ['', '   ', matchingFallback]), true);
  assert.equal(isSameAsFallback(candidate, [otherFallback]), false);
  assert.equal(isSameAsFallback(candidate, ['', '   ']), false);
  assert.equal(isSameAsFallback('', [matchingFallback]), false);
});

test('unit: maskOwnPath replaces multiple occurrences and ignores / or empty path', () => {
  const body = '<body>Error: route /admin not found. Link back to /admin.</body>';
  assert.equal(
    maskOwnPath(body, '/admin'),
    '<body>Error: route __VIBESANE_PATH__ not found. Link back to __VIBESANE_PATH__.</body>',
  );

  // Ignora caminho / ou vazio
  assert.equal(maskOwnPath('<body>Home /</body>', '/'), '<body>Home /</body>');
  assert.equal(maskOwnPath('<body>Home</body>', ''), '<body>Home</body>');
  assert.equal(maskOwnPath('', '/admin'), '');

  // Trata caminhos com caracteres especiais / encoded se aplicável
  const bodySpecial = '<body>Missing /admin%20test and /admin test</body>';
  assert.equal(
    maskOwnPath(bodySpecial, '/admin test'),
    '<body>Missing __VIBESANE_PATH__ and __VIBESANE_PATH__</body>',
  );
});

test('CLI: /admin 200 com HTML próprio -> 1 warning, exit 0, sem AI FIX PROMPT', async () => {
  const srv = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body><h1>Home Page</h1></body></html>');
      return;
    }
    if (url === '/admin') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body><h1>Secret Admin Area</h1><p>Confidential controls</p></body></html>');
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 0, 'Warning não altera o exit code (deve ser 0)');
    const out = io.getStdout();
    assert.match(out, /warning \[unauthenticated_admin_route\]/);
    assert.match(out, /GET \/admin answered 200 with its own content without credentials/);
    assert.doesNotMatch(out, /AI FIX PROMPT/, 'Warning não gera AI FIX PROMPT');
  } finally {
    await srv.close();
  }
});

test('CLI: SPA que devolve o mesmo index.html para tudo -> silêncio', async () => {
  const indexHtml = '<!doctype html><html><head><title>My SPA</title></head><body><div id="root"></div></body></html>';
  const srv = await startServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(indexHtml);
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 0);
    const out = io.getStdout();
    assert.doesNotMatch(out, /unauthenticated_admin_route/);
  } finally {
    await srv.close();
  }
});

test('CLI: catch-all 200 com página de não encontrado igual para qualquer caminho -> silêncio', async () => {
  const notFoundHtml = '<!doctype html><html><body><h1>404 - Page Not Found (Catch-all)</h1></body></html>';
  const srv = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body><h1>Welcome Home</h1></body></html>');
      return;
    }
    // Qualquer subrota (incluindo /admin, /dashboard, /debug e /vibesane-missing-...) recebe o mesmo HTML catch-all
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(notFoundHtml);
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 0);
    const out = io.getStdout();
    assert.doesNotMatch(out, /unauthenticated_admin_route/);
  } finally {
    await srv.close();
  }
});

test('CLI: /admin com formulário de login (input password) -> silêncio', async () => {
  const srv = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body><h1>Home</h1></body></html>');
      return;
    }
    if (url === '/admin') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body><h1>Admin Login</h1><form><input type="password" name="admin_pass" /></form></body></html>');
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 0);
    const out = io.getStdout();
    assert.doesNotMatch(out, /unauthenticated_admin_route/);
  } finally {
    await srv.close();
  }
});

test('CLI: /admin com 302 para /login, 401, 403 e 404 -> silêncio', async () => {
  // Teste 302
  const srvRedirect = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body><h1>Home</h1></body></html>');
      return;
    }
    if (url === '/admin') {
      res.writeHead(302, { Location: '/login' });
      res.end();
      return;
    }
    res.writeHead(404);
    res.end();
  });

  try {
    const io = createCaptureIO();
    const code = await main(['--port', String(srvRedirect.port)], io);
    assert.equal(code, 0);
    assert.doesNotMatch(io.getStdout(), /unauthenticated_admin_route/);
  } finally {
    await srvRedirect.close();
  }

  // Teste 401
  const srv401 = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body><h1>Home</h1></body></html>');
      return;
    }
    if (url === '/admin') {
      res.writeHead(401, { 'Content-Type': 'text/plain' });
      res.end('Unauthorized');
      return;
    }
    res.writeHead(404);
    res.end();
  });

  try {
    const io = createCaptureIO();
    const code = await main(['--port', String(srv401.port)], io);
    assert.equal(code, 0);
    assert.doesNotMatch(io.getStdout(), /unauthenticated_admin_route/);
  } finally {
    await srv401.close();
  }

  // Teste 403
  const srv403 = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body><h1>Home</h1></body></html>');
      return;
    }
    if (url === '/admin') {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }
    res.writeHead(404);
    res.end();
  });

  try {
    const io = createCaptureIO();
    const code = await main(['--port', String(srv403.port)], io);
    assert.equal(code, 0);
    assert.doesNotMatch(io.getStdout(), /unauthenticated_admin_route/);
  } finally {
    await srv403.close();
  }
});

test('CLI: /debug 200 JSON com segredo falso -> warning + secret_leak, exit 1', async () => {
  // Constrói a chave falsa sem disparar o linter de segredos do git
  const fakeKey = ['sb', 'secret', '1234567890abcdefghij'].join('_');

  const srv = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body><h1>Home</h1></body></html>');
      return;
    }
    if (url === '/debug') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ debug: true, serviceKey: fakeKey }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 1, 'Secret leak deve causar exit code 1');
    const out = io.getStdout();
    assert.match(out, /warning \[unauthenticated_admin_route\]/);
    assert.match(out, /GET \/debug answered 200 with its own content without credentials/);
    assert.match(out, /error \[secret_leak\]/);
    assert.match(out, /AI FIX PROMPT/, 'Erro de secret_leak deve gerar AI FIX PROMPT');
  } finally {
    await srv.close();
  }
});

test('CLI: /admin lento (> routeTimeoutMs) -> silêncio, sem slow_route', async () => {
  const srv = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body><h1>Home</h1></body></html>');
      return;
    }
    if (url === '/admin') {
      // Demora 200ms quando o timeout for 50ms
      setTimeout(() => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<h1>Late Admin</h1>');
      }, 200);
      return;
    }
    res.writeHead(404);
    res.end();
  });

  try {
    const res = await runVibesane({ port: srv.port, routeTimeoutMs: 50 });
    assert.equal(res.ok, true);
    // Não deve conter slow_route para /admin nem unauthenticated_admin_route
    const adminIssues = res.issues.filter((i) => i.route === '/admin');
    assert.equal(adminIssues.length, 0);
  } finally {
    await srv.close();
  }
});

test('CLI: nonce diferente a cada resposta na SPA -> silêncio', async () => {
  let counter = 0;
  const srv = await startServer((_req, res) => {
    counter += 1;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><head><script nonce="random_nonce_${counter}">init();</script></head><body><div id="root">App</div></body></html>`);
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 0);
    const out = io.getStdout();
    assert.doesNotMatch(out, /unauthenticated_admin_route/);
  } finally {
    await srv.close();
  }
});

test('CLI: servidor catch-all 200 que repete o caminho na página -> silêncio total', async () => {
  const srv = await startServer((req, res) => {
    const url = req.url ?? '/';
    if (url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body><h1>Home</h1></body></html>');
      return;
    }
    // Retorna 200 repetindo o caminho requisitado no HTML (ex.: <body>Nothing at /admin</body>)
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><body>Nothing at ${url}</body></html>`);
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 0);
    const out = io.getStdout();
    assert.doesNotMatch(out, /unauthenticated_admin_route/);
  } finally {
    await srv.close();
  }
});
