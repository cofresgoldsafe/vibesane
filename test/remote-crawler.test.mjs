import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { runVibesane, EXIT_CODES } from '../dist/index.js';

describe('Remote Crawler Integration (node:http offline test server)', () => {
  it('detecta falha de rede na raiz (porta fechada) e retorna could not reach sem prompt', async () => {
    // Porta alta aleatória sem servidor escutando em IP privado não-loopback
    // Ou usando um hostname não resolúvel
    const result = await runVibesane({
      url: 'http://unresolvable-domain-vibesane-test.invalid:9999',
      routeTimeoutMs: 500,
    });
    assert.equal(result.ok, false);
    assert.equal(result.issues.length, 0);
    assert.equal(result.aiPrompt, null);
    assert.match(result.message, /^vibesane: could not reach http:\/\/unresolvable-domain-vibesane-test\.invalid:9999/);
  });

  it('servidor HTTP puro: emite insecure_transport (error), missing_security_headers e cookies', async () => {
    const receivedHeaders = [];
    const server = http.createServer((req, res) => {
      receivedHeaders.push(req.headers);
      if (req.url === '/') {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Set-Cookie': 'session_token=secret123; Path=/',
        });
        res.end('<!DOCTYPE html><html><body><h1>Meu Site</h1><a href="/sub">Sub</a></body></html>');
      } else if (req.url === '/sub') {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
        });
        res.end('<!DOCTYPE html><html><body><h2>Subpage</h2></body></html>');
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // Invocação programática passando IP do servidor de teste com isRemote
      const result = await runVibesane({
        url: `http://127.0.0.1:${port}`,
        routeTimeoutMs: 1000,
      });

      assert.equal(result.ok, false);
      const transportErr = result.issues.find((i) => i.kind === 'insecure_transport');
      assert.ok(transportErr, 'expected insecure_transport error for cleartext HTTP without redirect');
      assert.equal(transportErr.severity, 'error');

      const cookieWarn = result.issues.find((i) => i.kind === 'insecure_cookie');
      assert.ok(cookieWarn, 'expected insecure_cookie warning for missing HttpOnly');

      const secHeaders = result.issues.filter((i) => i.kind === 'missing_security_headers');
      assert.ok(secHeaders.length > 0, 'expected missing_security_headers warnings');

      // AI FIX PROMPT foi gerado com as instruções ordenadas
      assert.ok(result.aiPrompt);
      assert.match(result.aiPrompt, /Instruction/);

      // User-Agent foi transmitido
      assert.ok(receivedHeaders.some((h) => h['user-agent'] && h['user-agent'].startsWith('vibesane/')));
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('detecta sourcemap exposto (.map) e stack trace leak em erro 500', async () => {
    const server = http.createServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
        });
        res.end(
          '<!DOCTYPE html><html><head><script src="/bundle.js"></script></head><body><a href="/crash">Crash</a></body></html>',
        );
      } else if (req.url === '/bundle.js') {
        res.writeHead(200, { 'Content-Type': 'application/javascript' });
        res.end('console.log("hello");\n//# sourceMappingURL=/bundle.js.map');
      } else if (req.url === '/bundle.js.map') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            version: 3,
            file: 'bundle.js',
            sources: ['src/app.ts'],
            mappings: 'AAAA',
          }),
        );
      } else if (req.url === '/crash') {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Error: Database connection lost\n    at queryDatabase (/var/task/app/db.ts:34:12)');
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const result = await runVibesane({
        url: `http://127.0.0.1:${port}`,
        routeTimeoutMs: 1000,
      });

      const mapIssue = result.issues.find((i) => i.kind === 'exposed_source_map');
      assert.ok(mapIssue, 'expected exposed_source_map warning');
      assert.equal(mapIssue.severity, 'warning');

      const stackIssue = result.issues.find((i) => i.kind === 'stack_trace_leak');
      assert.ok(stackIssue, 'expected stack_trace_leak error');
      assert.equal(stackIssue.severity, 'error');
      assert.match(stackIssue.detail, /queryDatabase/);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('respeita o teto de 40 requisições e concorrência máxima de 2 com 60 links e servidor lento', async () => {
    let activeConnections = 0;
    let maxObservedConcurrency = 0;
    let totalRequests = 0;

    const server = http.createServer(async (req, res) => {
      totalRequests++;
      activeConnections++;
      if (activeConnections > maxObservedConcurrency) {
        maxObservedConcurrency = activeConnections;
      }

      await new Promise((r) => setTimeout(r, 25));
      activeConnections--;

      if (req.url === '/') {
        // Gera 60 links internos para testar o corte estrito no teto
        const links = Array.from({ length: 60 }, (_, i) => `<a href="/route-${i}">R${i}</a>`).join('');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<!DOCTYPE html><html><body>${links}</body></html>`);
      } else {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('OK');
      }
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const result = await runVibesane({
        url: `http://127.0.0.1:${port}`,
        maxRoutes: 70,
        routeTimeoutMs: 1000,
      });

      assert.ok(totalRequests <= 40, `expected total requests <= 40, observed ${totalRequests}`);
      assert.equal(totalRequests, 40, `expected exactly 40 requests reached, observed ${totalRequests}`);
      assert.ok(maxObservedConcurrency <= 2, `expected concurrency <= 2, observed ${maxObservedConcurrency}`);
      assert.ok(result.skippedRoutes.length > 0, 'expected some routes to be skipped due to request limit');
      assert.match(result.message, /request limit reached/);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('modo local (-p): servidor com 500 + stack trace e Set-Cookie session_id sem HttpOnly não aciona as regras novas (idêntico a 0.1.15)', async () => {
    const server = http.createServer((req, res) => {
      res.writeHead(500, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Set-Cookie': 'session_id=abc123secret; Path=/',
      });
      res.end('Error: Database connection failed\n    at queryDb (/app/db.js:10:5)');
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // Executa com porta local (modo local v0.1.15)
      const result = await runVibesane({
        port,
        routeTimeoutMs: 1000,
      });

      assert.equal(result.ok, false);
      // Exatamente 1 issue: http_error (como na 0.1.15)
      assert.equal(result.issues.length, 1);
      assert.equal(result.issues[0].kind, 'http_error');
      assert.equal(result.issues[0].severity, 'error');

      // Nenhuma das regras novas é emitida em modo local
      assert.equal(result.issues.some((i) => i.kind === 'stack_trace_leak'), false);
      assert.equal(result.issues.some((i) => i.kind === 'insecure_cookie'), false);
      assert.equal(result.issues.some((i) => i.kind === 'missing_security_headers'), false);
      assert.equal(result.issues.some((i) => i.kind === 'insecure_transport'), false);
      assert.equal(result.issues.some((i) => i.kind === 'exposed_source_map'), false);

      // AI prompt tem apenas instruction de code
      assert.ok(result.aiPrompt);
      assert.match(result.aiPrompt, /Instruction: Fix only the error pointed out above/);
      assert.doesNotMatch(result.aiPrompt, /Instruction \(stack trace\)/);
      assert.doesNotMatch(result.aiPrompt, /Instruction \(cookies\)/);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('agrupa cookies com mesmo nome e mesmo problema em 1 única issue para o site todo (rota da 1ª ocorrência)', async () => {
    const server = http.createServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, {
          'Content-Type': 'text/html',
          'Set-Cookie': 'session_id=token1; Path=/',
        });
        res.end('<!DOCTYPE html><html><body><a href="/sub1">S1</a><a href="/sub2">S2</a></body></html>');
      } else if (req.url === '/sub1') {
        res.writeHead(200, {
          'Content-Type': 'text/html',
          'Set-Cookie': 'session_id=token2; Path=/',
        });
        res.end('<!DOCTYPE html><html><body>Sub1</body></html>');
      } else if (req.url === '/sub2') {
        res.writeHead(200, {
          'Content-Type': 'text/html',
          'Set-Cookie': 'session_id=token3; Path=/',
        });
        res.end('<!DOCTYPE html><html><body>Sub2</body></html>');
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const result = await runVibesane({
        url: `http://127.0.0.1:${port}`,
        routeTimeoutMs: 1000,
      });

      const cookieIssues = result.issues.filter((i) => i.kind === 'insecure_cookie');
      assert.equal(cookieIssues.length, 1, 'expected exactly 1 insecure_cookie issue despite appearing on 3 routes');
      assert.equal(cookieIssues[0].route, '/');
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('servidor lento na raiz: quando o tempo excede routeTimeoutMs, runVibesane não lança exceção e devolve could not reach (timeout)', async () => {
    let timer;
    const server = http.createServer((req, res) => {
      // Simula servidor que demora 6s para responder a raiz
      timer = setTimeout(() => {
        if (!res.writableEnded) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<!DOCTYPE html><html><body>Late</body></html>');
        }
      }, 6000);
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const result = await runVibesane({
        url: `http://127.0.0.1:${port}`,
        routeTimeoutMs: 150,
      });

      assert.equal(result.ok, false);
      assert.equal(result.issues.length, 0);
      assert.equal(result.aiPrompt, null);
      assert.equal(result.message, `vibesane: could not reach http://127.0.0.1:${port} (timeout)`);
    } finally {
      clearTimeout(timer);
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
