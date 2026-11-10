import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { main } from '../dist/cli.js';
import { EXIT_CODES } from '../dist/index.js';

describe('vibesane CLI --url mode', () => {
  it('--help exibe a nova opção --url <url>', async () => {
    const stdout = [];
    const code = await main(['--help'], {
      stdout: (m) => stdout.push(m),
      stderr: () => {},
    });
    assert.equal(code, EXIT_CODES.OK);
    const output = stdout.join('\n');
    assert.match(output, /--url <url>\s+Target published web URL \(http:\/\/ or https:\/\/\)/);
  });

  it('rejeita --url e -p / --port simultâneos com código 2 e mensagem de mútua exclusão', async () => {
    const stderr = [];
    const code = await main(['--url', 'https://example.com', '-p', '3000'], {
      stdout: () => {},
      stderr: (m) => stderr.push(m),
    });
    assert.equal(code, EXIT_CODES.USAGE_ERROR);
    assert.equal(
      stderr.join('\n'),
      'vibesane: error: options --url and --port cannot be used together',
    );
  });

  it('rejeita --url repetido com código 2', async () => {
    const stderr = [];
    const code = await main(
      ['--url', 'https://site-a.com', '--url', 'https://site-b.com'],
      {
        stdout: () => {},
        stderr: (m) => stderr.push(m),
      },
    );
    assert.equal(code, EXIT_CODES.USAGE_ERROR);
    assert.equal(
      stderr.join('\n'),
      'vibesane: error: option --url cannot be specified multiple times',
    );
  });

  it('rejeita --url com URL malformada com código 2', async () => {
    const stderr = [];
    const code = await main(['--url', 'not a valid url'], {
      stdout: () => {},
      stderr: (m) => stderr.push(m),
    });
    assert.equal(code, EXIT_CODES.USAGE_ERROR);
    assert.match(stderr.join('\n'), /invalid url "not a valid url" \(malformed URL\)/);
  });

  it('rejeita esquema não HTTP/HTTPS (ex: ftp://) com código 2', async () => {
    const stderr = [];
    const code = await main(['--url', 'ftp://ftp.example.com'], {
      stdout: () => {},
      stderr: (m) => stderr.push(m),
    });
    assert.equal(code, EXIT_CODES.USAGE_ERROR);
    assert.match(
      stderr.join('\n'),
      /only http:\/\/ and https:\/\/ are supported/,
    );
  });

  it('rejeita loopback localhost com código 2 e sugere -p', async () => {
    const stderr = [];
    const code = await main(['--url', 'http://localhost:3000'], {
      stdout: () => {},
      stderr: (m) => stderr.push(m),
    });
    assert.equal(code, EXIT_CODES.USAGE_ERROR);
    assert.equal(
      stderr.join('\n'),
      'vibesane: error: --url cannot point to localhost/loopback; use -p <port> instead',
    );
  });

  it('rejeita subdomínio *.localhost com código 2 e sugere -p', async () => {
    const stderr = [];
    const code = await main(['--url', 'http://sub.localhost:5173'], {
      stdout: () => {},
      stderr: (m) => stderr.push(m),
    });
    assert.equal(code, EXIT_CODES.USAGE_ERROR);
    assert.equal(
      stderr.join('\n'),
      'vibesane: error: --url cannot point to localhost/loopback; use -p <port> instead',
    );
  });

  it('rejeita IPv4 loopback 127.0.0.1 e bloco 127.0.0.0/8 com código 2', async () => {
    for (const host of ['127.0.0.1', '127.1.2.3', '0.0.0.0']) {
      const stderr = [];
      const code = await main(['--url', `http://${host}:8080`], {
        stdout: () => {},
        stderr: (m) => stderr.push(m),
      });
      assert.equal(code, EXIT_CODES.USAGE_ERROR);
      assert.equal(
        stderr.join('\n'),
        'vibesane: error: --url cannot point to localhost/loopback; use -p <port> instead',
      );
    }
  });

  it('rejeita IPv6 loopback ::1 e [::1] com código 2', async () => {
    for (const raw of ['http://[::1]:8080']) {
      const stderr = [];
      const code = await main(['--url', raw], {
        stdout: () => {},
        stderr: (m) => stderr.push(m),
      });
      assert.equal(code, EXIT_CODES.USAGE_ERROR);
      assert.equal(
        stderr.join('\n'),
        'vibesane: error: --url cannot point to localhost/loopback; use -p <port> instead',
      );
    }
  });

  it('rejeita localhost com ponto final e IPv4 mapeado em IPv6 ([::ffff:127.x.x.x] e [::ffff:7f00:1])', async () => {
    const loopbacks = [
      'http://localhost.:3000',
      'http://app.localhost.:8080',
      'http://[::ffff:127.0.0.1]:3000',
      'http://[::ffff:127.0.0.2]:8080',
      'http://[::ffff:7f00:1]:3000',
    ];
    for (const raw of loopbacks) {
      const stderr = [];
      const code = await main(['--url', raw], {
        stdout: () => {},
        stderr: (m) => stderr.push(m),
      });
      assert.equal(code, EXIT_CODES.USAGE_ERROR, `expected USAGE_ERROR for ${raw}`);
      assert.equal(
        stderr.join('\n'),
        'vibesane: error: --url cannot point to localhost/loopback; use -p <port> instead',
      );
    }
  });

  it('não suporta atalho curto -u (rejeitado como flag desconhecida)', async () => {
    const stderr = [];
    const code = await main(['-u', 'https://example.com'], {
      stdout: () => {},
      stderr: (m) => stderr.push(m),
    });
    assert.equal(code, EXIT_CODES.USAGE_ERROR);
    assert.match(stderr.join('\n'), /unknown option '-u'/i);
  });
});
