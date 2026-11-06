import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { main } from '../dist/cli.js';
import { runVibesane, EXIT_CODES } from '../dist/index.js';

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
    outLines: out,
    errLines: err,
  };
}

/**
 * Starts an ephemeral HTTP server on 127.0.0.1.
 * @returns {Promise<{ server: import('node:http').Server, port: number, close: () => Promise<void> }>}
 */
function startEphemeralHttpServer() {
  return new Promise((resolve, reject) => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body>ok</body></html>');
    });
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

describe('vibesane CLI & Programmatic API (BDD)', () => {
  it('runVibesane programático exporta EXIT_CODES, conecta a servidor ativo e valida faixas de porta', async () => {
    assert.deepEqual(EXIT_CODES, { OK: 0, SANITY_FAILURE: 1, USAGE_ERROR: 2 });

    const srv = await startEphemeralHttpServer();
    try {
      const resPort = await runVibesane({ port: srv.port });
      assert.equal(resPort.ok, true);
      assert.equal(resPort.port, srv.port);
      assert.equal(resPort.url, `http://localhost:${srv.port}`);
      assert.match(
        resPort.message,
        /^vibesane: connected to http:\/\/localhost:\d+ \(\d+ms\)$/,
      );
    } finally {
      await srv.close();
    }

    await assert.rejects(() => runVibesane({ port: -1 }), RangeError);
    await assert.rejects(() => runVibesane({ port: 70000 }), RangeError);
    await assert.rejects(() => runVibesane({ port: 80.5 }), RangeError);
  });

  describe('porta válida (--port, -p, --port=<val> e limites 1..65535)', () => {
    it('aceita --port <port>, -p <port> e --port=<port> conectando a servidor HTTP ativo', async () => {
      const srv = await startEphemeralHttpServer();
      try {
        const portStr = String(srv.port);
        const flagVariants = [
          ['--port', portStr],
          ['-p', portStr],
          [`--port=${portStr}`],
        ];

        for (const argv of flagVariants) {
          const res = await runCli(argv);
          assert.equal(res.code, EXIT_CODES.OK);
          assert.equal(res.code, 0);
          assert.equal(res.stderr, '');
          assert.match(
            res.stdout,
            /^vibesane: connected to http:\/\/localhost:\d+ \(\d+ms\)$/,
          );
        }
      } finally {
        await srv.close();
      }
    });

    it('main(["--port", "<closedPort>"]) retorna EXIT_CODES.SANITY_FAILURE (1) e erro em stderr', async () => {
      const srv = await startEphemeralHttpServer();
      const closedPort = srv.port;
      await srv.close();

      const res = await runCli(['--port', String(closedPort)]);
      assert.equal(res.code, EXIT_CODES.SANITY_FAILURE);
      assert.equal(res.code, 1);
      assert.equal(res.stdout, '');
      assert.ok(
        res.stderr.includes(`vibesane: no active server found on port ${closedPort}`),
        `stderr inesperado: ${res.stderr}`,
      );
    });

    it('aceita limites de faixa 1 e 65535 sem erro de uso (código !== 2)', async () => {
      for (const boundary of ['1', '65535']) {
        const res = await runCli(['--port', boundary]);
        assert.notEqual(res.code, EXIT_CODES.USAGE_ERROR);
      }
    });
  });

  describe('flags informativas (--help, -h, --version, -v)', () => {
    it('--help retorna 0 e exibe Usage: vibesane', async () => {
      const res = await runCli(['--help']);
      assert.equal(res.code, 0);
      assert.match(res.stdout, /Usage: vibesane/);
      assert.equal(res.stderr, '');
    });

    it('-h retorna 0 e exibe Usage: vibesane', async () => {
      const res = await runCli(['-h']);
      assert.equal(res.code, 0);
      assert.match(res.stdout, /Usage: vibesane/);
      assert.equal(res.stderr, '');
    });

    it('--version retorna 0 e exibe a versão de package.json (0.1.0)', async () => {
      const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
      const res = await runCli(['--version']);
      assert.equal(res.code, 0);
      assert.equal(res.stdout.trim(), pkg.version);
      assert.equal(res.stdout.trim(), '0.1.0');
      assert.equal(res.stderr, '');
    });

    it('-v retorna 0 e exibe a versão de package.json (0.1.0)', async () => {
      const res = await runCli(['-v']);
      assert.equal(res.code, 0);
      assert.equal(res.stdout.trim(), '0.1.0');
      assert.equal(res.stderr, '');
    });
  });

  describe('precedência de flags', () => {
    it('main(["--help", "--port", "abc"]) retorna 0, exibe help e ignora porta inválida', async () => {
      const res = await runCli(['--help', '--port', 'abc']);
      assert.equal(res.code, 0);
      assert.match(res.stdout, /Usage: vibesane/);
      assert.equal(res.stderr, '');
    });

    it('main(["--help", "--version"]) retorna 0 e exibe help (--help vence --version)', async () => {
      const res = await runCli(['--help', '--version']);
      assert.equal(res.code, 0);
      assert.match(res.stdout, /Usage: vibesane/);
      assert.equal(res.stderr, '');
    });

    it('main(["--version", "--port", "abc"]) retorna 0, exibe versão e ignora porta inválida', async () => {
      const res = await runCli(['--version', '--port', 'abc']);
      assert.equal(res.code, 0);
      assert.equal(res.stdout.trim(), '0.1.0');
      assert.equal(res.stderr, '');
    });

    it('main(["--help", "--unknown"]) retorna 0 e exibe help', async () => {
      const res = await runCli(['--help', '--unknown']);
      assert.equal(res.code, 0);
      assert.match(res.stdout, /Usage: vibesane/);
      assert.equal(res.stderr, '');
    });

    it('main(["--help", "--port"]) sem valor para --port retorna 0 e exibe help', async () => {
      const res = await runCli(['--help', '--port']);
      assert.equal(res.code, 0);
      assert.match(res.stdout, /Usage: vibesane/);
      assert.equal(res.stderr, '');
    });

    it('main(["--version", "--unknown"]) retorna 0 e exibe versão', async () => {
      const res = await runCli(['--version', '--unknown']);
      assert.equal(res.code, 0);
      assert.equal(res.stdout.trim(), '0.1.0');
      assert.equal(res.stderr, '');
    });
  });

  describe('erros de uso (EXIT_CODES.USAGE_ERROR === 2)', () => {
    const errorCases = [
      { name: 'flag desconhecida (--unknown)', argv: ['--unknown'] },
      { name: 'argumento posicional solto (foo)', argv: ['foo'] },
      { name: '--port sem valor', argv: ['--port'] },
      { name: 'porta não numérica (--port abc)', argv: ['--port', 'abc'] },
      { name: 'porta não numérica inline (--port=abc)', argv: ['--port=abc'] },
      { name: 'porta com sufixo inválido (--port 8000abc)', argv: ['--port', '8000abc'] },
      { name: 'porta fora de faixa 0 (--port 0)', argv: ['--port', '0'] },
      { name: 'porta fora de faixa 65536 (--port 65536)', argv: ['--port', '65536'] },
      { name: 'porta negativa (--port -1)', argv: ['--port', '-1'] },
      { name: '--port repetido (--port 3000 --port 4000)', argv: ['--port', '3000', '--port', '4000'] },
      { name: 'porta com zero à esquerda (--port 08000)', argv: ['--port', '08000'] },
      { name: 'porta vazia (--port "")', argv: ['--port', ''] },
      { name: 'porta com sinal positivo (--port +8000)', argv: ['--port', '+8000'] },
      { name: 'porta decimal (--port 8000.5)', argv: ['--port', '8000.5'] },
      { name: 'porta com espaços (--port " 8000 ")', argv: ['--port', ' 8000 '] },
    ];

    for (const { name, argv } of errorCases) {
      it(`rejeita ${name} com código 2 e mensagem em stderr`, async () => {
        const res = await runCli(argv);
        assert.equal(res.code, EXIT_CODES.USAGE_ERROR);
        assert.equal(res.code, 2);
        assert.equal(res.stdout, '');
        assert.ok(res.stderr.length > 0, 'stderr não deve estar vazio');
      });
    }
  });

  describe('empacotamento, binário e formatação LF', () => {
    it('smoke test do binário executável bin/vibesane.js --version', () => {
      const output = execFileSync(process.execPath, ['bin/vibesane.js', '--version'], {
        encoding: 'utf8',
      });
      assert.equal(output, '0.1.0\n');
    });

    it('bin/vibesane.js possui quebras de linha LF e shebang válido', () => {
      const raw = readFileSync('bin/vibesane.js', 'utf8');
      assert.ok(!raw.includes('\r\n'), 'bin/vibesane.js não deve conter CRLF (\\r\\n)');
      assert.ok(
        raw.startsWith('#!/usr/bin/env node\n'),
        'bin/vibesane.js deve iniciar com #!/usr/bin/env node\\n',
      );
    });

    it('npm pack --dry-run --json gera pacote < 500 KB contendo apenas arquivos permitidos', () => {
      const res =
        process.platform === 'win32'
          ? spawnSync('npm pack --dry-run --json', { shell: true, encoding: 'utf8' })
          : spawnSync('npm', ['pack', '--dry-run', '--json'], { encoding: 'utf8' });
      assert.equal(res.status, 0, `npm pack falhou: ${res.stderr}`);
      const pack = JSON.parse(res.stdout);
      assert.ok(Array.isArray(pack) && pack.length > 0, 'Saída JSON do npm pack inválida');
      assert.ok(
        pack[0].size < 500 * 1024,
        `Tamanho do pacote (${pack[0].size} bytes) excedeu 500 KB`,
      );

      const filePaths = pack[0].files.map((f) => f.path);
      assert.ok(filePaths.includes('bin/vibesane.js'), 'Deve incluir bin/vibesane.js');
      assert.ok(filePaths.includes('dist/cli.js'), 'Deve incluir dist/cli.js');
      assert.ok(filePaths.includes('dist/index.js'), 'Deve incluir dist/index.js');
      assert.ok(
        !filePaths.some((p) => p.startsWith('src/')),
        'Não deve incluir arquivos de src/',
      );
      assert.ok(
        !filePaths.some((p) => p.startsWith('test/')),
        'Não deve incluir arquivos de test/',
      );
    });
  });
});
