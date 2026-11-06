import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { DEFAULT_PORTS, detectServer, probeTcpPort, readBoundedTextBody } from '../dist/scanner/port-detector.js';
import { runVibesane } from '../dist/index.js';

/**
 * Starts an ephemeral HTTP server on the given host.
 * @param {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void} handler
 * @param {string} [host='127.0.0.1']
 * @returns {Promise<{ server: import('node:http').Server, port: number, close: () => Promise<void> }>}
 */
function startHttpServer(handler, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const server = createServer(handler);
    server.once('error', reject);
    server.listen(0, host, () => {
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
 * Starts an ephemeral raw TCP server on the given host.
 * @param {(socket: import('node:net').Socket) => void} onConnection
 * @param {string} [host='127.0.0.1']
 * @returns {Promise<{ server: import('node:net').Server, port: number, close: () => Promise<void> }>}
 */
function startTcpServer(onConnection, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const sockets = new Set();
    const server = createNetServer((socket) => {
      sockets.add(socket);
      socket.on('error', () => {});
      socket.once('close', () => sockets.delete(socket));
      onConnection(socket);
    });
    server.once('error', reject);
    server.listen(0, host, () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      resolve({
        server,
        port,
        close: () =>
          new Promise((resClose) => {
            for (const s of sockets) {
              s.destroy();
            }
            server.close(() => resClose());
          }),
      });
    });
  });
}

/**
 * Allocates an ephemeral TCP port and immediately closes the server to get an unused port.
 * @returns {Promise<number>}
 */
async function getClosedPort() {
  const srv = await startTcpServer((s) => s.destroy());
  const { port } = srv;
  await srv.close();
  return port;
}

describe('Port Detector & Local Server Scanner (BDD)', () => {
  it('1. DEFAULT_PORTS contém exatamente [3000, 3001, 5173, 5174, 8080, 8000, 4321] e não inclui 5000', () => {
    assert.deepEqual(
      [...DEFAULT_PORTS],
      [3000, 3001, 5173, 5174, 8080, 8000, 4321],
    );
    assert.equal(DEFAULT_PORTS.includes(5000), false);
  });

  it('2. IPv4 puro (127.0.0.1): detecta servidor HTTP ouvindo exclusivamente em 127.0.0.1', async () => {
    const srv = await startHttpServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body>ok</body></html>');
    }, '127.0.0.1');

    try {
      const tcp = await probeTcpPort(srv.port, 500);
      assert.equal(tcp.open, true);
      assert.equal(tcp.host, '127.0.0.1');

      const result = await detectServer({ port: srv.port });
      assert.equal(result.ok, true);
      assert.equal(result.port, srv.port);
      assert.equal(result.host, '127.0.0.1');
      assert.equal(result.url, `http://localhost:${srv.port}`);
      assert.equal(result.statusCode, 200);
      assert.equal(result.reason, undefined);
    } finally {
      await srv.close();
    }
  });

  it('3. IPv6 puro (::1): detecta servidor HTTP ouvindo exclusivamente em ::1 (ou pula se indisponível)', async (t) => {
    let srv;
    try {
      srv = await startHttpServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ipv6-ok');
      }, '::1');
    } catch (err) {
      if (err && (err.code === 'EADDRNOTAVAIL' || err.code === 'EAFNOSUPPORT')) {
        t.skip('IPv6 loopback ::1 not available');
        return;
      }
      throw err;
    }

    try {
      const result = await detectServer({ port: srv.port });
      assert.equal(result.ok, true);
      assert.equal(result.port, srv.port);
      assert.equal(result.host, '::1');
      assert.equal(result.url, `http://localhost:${srv.port}`);
      assert.equal(result.statusCode, 200);
    } finally {
      await srv.close();
    }
  });

  it('4. Status HTTP 404 e 500: servidor respondendo 404 ou 500 na raiz / ainda é detectado como ativo', async () => {
    const srv500 = await startHttpServer((_req, res) => {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal Server Error');
    });
    const srv404 = await startHttpServer((_req, res) => {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    });

    try {
      const res500 = await detectServer({ port: srv500.port });
      assert.equal(res500.ok, true);
      assert.equal(res500.port, srv500.port);
      assert.equal(res500.statusCode, 500);
      assert.equal(res500.reason, undefined);

      const res404 = await detectServer({ port: srv404.port });
      assert.equal(res404.ok, true);
      assert.equal(res404.port, srv404.port);
      assert.equal(res404.statusCode, 404);
      assert.equal(res404.reason, undefined);
    } finally {
      await srv500.close();
      await srv404.close();
    }
  });

  it('5. Desempate determinístico e alsoActivePorts conforme ordem de prioridade', async () => {
    const srvA = await startHttpServer((_req, res) => {
      res.writeHead(200);
      res.end('server A');
    });
    const srvB = await startHttpServer((_req, res) => {
      res.writeHead(200);
      res.end('server B');
    });

    try {
      const portA = srvA.port;
      const portB = srvB.port;

      const detAB = await detectServer({ ports: [portA, portB] });
      assert.equal(detAB.ok, true);
      assert.equal(detAB.port, portA);
      assert.deepEqual(detAB.alsoActivePorts, [portB]);

      const vibeAB = await runVibesane({ ports: [portA, portB] });
      assert.equal(vibeAB.ok, true);
      assert.equal(vibeAB.port, portA);
      assert.deepEqual(vibeAB.alsoActivePorts, [portB]);
      assert.match(
        vibeAB.message,
        /vibesane: connected to http:\/\/localhost:\d+ \(\d+ms\) \(also active: \d+\)/,
      );

      const detBA = await detectServer({ ports: [portB, portA] });
      assert.equal(detBA.ok, true);
      assert.equal(detBA.port, portB);
      assert.deepEqual(detBA.alsoActivePorts, [portA]);

      const vibeBA = await runVibesane({ ports: [portB, portA] });
      assert.equal(vibeBA.ok, true);
      assert.equal(vibeBA.port, portB);
      assert.deepEqual(vibeBA.alsoActivePorts, [portA]);
    } finally {
      await srvA.close();
      await srvB.close();
    }
  });

  describe('6. Curto-circuito por prioridade', () => {
    it('6a. Porta de maior prioridade aberta retorna sem esperar as outras portas fechadas', async () => {
      const fastSrv = await startHttpServer((_req, res) => {
        res.writeHead(200);
        res.end('fast');
      });
      const closedPort = await getClosedPort();

      try {
        const start = performance.now();
        const result = await detectServer({
          ports: [fastSrv.port, closedPort],
          tcpTimeoutMs: 400,
          httpTimeoutMs: 600,
        });
        const elapsed = performance.now() - start;

        assert.equal(result.ok, true);
        assert.equal(result.port, fastSrv.port);
        assert.ok(
          elapsed < 250,
          `Esperava curto-circuito rápido (<250ms), mas levou ${Math.round(elapsed)}ms`,
        );
      } finally {
        await fastSrv.close();
      }
    });

    it('6b. Porta de menor prioridade aberta só vence após as de maior prioridade falharem/esgotarem', async () => {
      const closedPort = await getClosedPort();
      const openSrv = await startHttpServer((_req, res) => {
        res.writeHead(200);
        res.end('open');
      });

      try {
        const result = await detectServer({
          ports: [closedPort, openSrv.port],
          tcpTimeoutMs: 120,
          httpTimeoutMs: 500,
        });

        assert.equal(result.ok, true);
        assert.equal(result.port, openSrv.port);
      } finally {
        await openSrv.close();
      }
    });
  });

  describe('7. Distinção entre non_http e http_timeout', () => {
    it('7a. non_http: porta TCP aberta que responde bytes inválidos / fecha socket sem HTTP', async () => {
      const tcpSrv = await startTcpServer((socket) => {
        socket.end('NOT_HTTP_PROTOCOL\r\n\r\n');
      });

      try {
        const res = await runVibesane({ port: tcpSrv.port });
        assert.equal(res.ok, false);
        assert.equal(res.port, tcpSrv.port);
        assert.equal(res.reason, 'non_http');
        assert.equal(
          res.message,
          `vibesane: port ${tcpSrv.port} is open but did not respond to HTTP`,
        );
      } finally {
        await tcpSrv.close();
      }
    });

    it('7b. http_timeout: servidor HTTP aceita conexão mas não responde dentro de httpTimeoutMs', async () => {
      const hangingHttpSrv = await startHttpServer((_req, _res) => {
        // Intentionally never calls res.end()
      });

      try {
        const res = await runVibesane({
          port: hangingHttpSrv.port,
          httpTimeoutMs: 100,
        });
        assert.equal(res.ok, false);
        assert.equal(res.port, hangingHttpSrv.port);
        assert.equal(res.reason, 'http_timeout');
        assert.ok(
          res.message.includes(
            'accepted the connection but took >100ms to respond (still compiling?)',
          ),
          `Mensagem inesperada: ${res.message}`,
        );
      } finally {
        await hangingHttpSrv.close();
      }
    });
  });

  it('8. Nenhuma porta ativa (no_server): porta única e múltiplas portas fechadas', async () => {
    const closedPort1 = await getClosedPort();
    const closedPort2 = await getClosedPort();

    const singleRes = await runVibesane({
      port: closedPort1,
      tcpTimeoutMs: 100,
    });
    assert.equal(singleRes.ok, false);
    assert.equal(singleRes.port, null);
    assert.equal(singleRes.reason, 'no_server');
    assert.equal(
      singleRes.message,
      `vibesane: no active server found on port ${closedPort1}`,
    );

    const multiRes = await runVibesane({
      ports: [closedPort1, closedPort2],
      tcpTimeoutMs: 100,
    });
    assert.equal(multiRes.ok, false);
    assert.equal(multiRes.port, null);
    assert.equal(multiRes.reason, 'no_server');
    assert.equal(
      multiRes.message,
      `vibesane: no active server found on ports ${closedPort1}, ${closedPort2}`,
    );
  });

  describe('9. Validação de fronteira e deduplicação (ports duplicadas, lista vazia e timeouts inválidos)', () => {
    it('9a. deduplica ports repetidas sem gerar falso-positivo em alsoActivePorts', async () => {
      const srv = await startHttpServer((_req, res) => {
        res.writeHead(200);
        res.end('dedup');
      });

      try {
        const res = await runVibesane({ ports: [srv.port, srv.port] });
        assert.equal(res.ok, true);
        assert.equal(res.port, srv.port);
        assert.deepEqual(res.checkedPorts, [srv.port]);
        assert.deepEqual(res.alsoActivePorts, []);
        assert.equal(res.message.includes('also active'), false);
      } finally {
        await srv.close();
      }
    });

    it('9b. rejeita lista de portas vazia (ports: []) com RangeError', async () => {
      await assert.rejects(() => detectServer({ ports: [] }), RangeError);
      await assert.rejects(() => runVibesane({ ports: [] }), RangeError);
    });

    it('9c. rejeita timeouts inválidos (<= 0, NaN, Infinity) em probeTcpPort e detectServer com RangeError', async () => {
      for (const badTimeout of [0, -1, -10, NaN, Infinity]) {
        await assert.rejects(async () => probeTcpPort(3000, badTimeout), RangeError);
        await assert.rejects(
          () => detectServer({ port: 3000, tcpTimeoutMs: badTimeout }),
          RangeError,
        );
        await assert.rejects(
          () => detectServer({ port: 3000, httpTimeoutMs: badTimeout }),
          RangeError,
        );
      }
    });
  });

  describe('10. Bounded Text Body Reader (tamanho exato, corte por size, timeout e stream error)', () => {
    it('10a. corpo com tamanho EXATAMENTE igual a maxBytes é consumido por completo sem ser truncado', async () => {
      const exactSize = 1024;
      const payload = 'x'.repeat(exactSize);
      const srv = await startHttpServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(payload);
      });

      try {
        const res = await fetch(`http://127.0.0.1:${srv.port}`);
        const result = await readBoundedTextBody(res, exactSize, 500);
        assert.equal(result.body.length, exactSize);
        assert.equal(result.body, payload);
        assert.equal(result.truncated, false);
        assert.equal(result.truncatedReason, null);
      } finally {
        await srv.close();
      }
    });

    it('10b. corpo com maxBytes + 1 é cortado com truncated: true e truncatedReason: "size"', async () => {
      const maxSize = 1024;
      const payload = 'y'.repeat(maxSize + 100);
      const srv = await startHttpServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(payload);
      });

      try {
        const res = await fetch(`http://127.0.0.1:${srv.port}`);
        const result = await readBoundedTextBody(res, maxSize, 500);
        assert.equal(result.body.length, maxSize);
        assert.equal(result.truncated, true);
        assert.equal(result.truncatedReason, 'size');
      } finally {
        await srv.close();
      }
    });

    it('10c. leitura que estoura o timeout é cortada com truncated: true e truncatedReason: "timeout"', async () => {
      const srv = await startHttpServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.write('primeira_parte');
        // Não fecha a conexão imediatamente, espera 200ms
        setTimeout(() => {
          res.end('_segunda_parte');
        }, 200);
      });

      try {
        const res = await fetch(`http://127.0.0.1:${srv.port}`);
        const result = await readBoundedTextBody(res, 1024 * 1024, 50);
        assert.equal(result.truncated, true);
        assert.equal(result.truncatedReason, 'timeout');
      } finally {
        await srv.close();
      }
    });

    it('10d. erro no stream é marcado com truncated: true e truncatedReason: "error"', async () => {
      const srv = await startHttpServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.write('inicio');
        // Destrói o socket abruptamente simulando falha de rede/stream
        setTimeout(() => {
          res.destroy();
        }, 20);
      });

      try {
        const res = await fetch(`http://127.0.0.1:${srv.port}`);
        const result = await readBoundedTextBody(res, 1024 * 1024, 500);
        assert.equal(result.truncated, true);
        assert.equal(result.truncatedReason, 'error');
      } finally {
        await srv.close();
      }
    });
  });
});
