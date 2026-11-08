import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { runVibesane, EXIT_CODES } from '../dist/index.js';
import {
  inspectExposedEnvBody,
  inspectExposedGitConfigBody,
  ENV_FILE_PATHS,
} from '../dist/scanner/route-crawler.js';
import {
  generateAiFixPrompt,
  EXPOSED_FILE_INSTRUCTION,
  SECRET_LEAK_INSTRUCTION,
  CODE_ERROR_INSTRUCTION,
} from '../dist/reporter/ai-prompt-gen.js';

describe('Exposed Files Scanner (/.env & /.git/config) — v0.1.6', () => {
  async function startServer(handler) {
    const server = http.createServer(handler);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    return {
      port,
      async close() {
        await new Promise((resolve) => server.close(resolve));
      },
    };
  }

  it('unit: inspectExposedEnvBody extracts only variable names (up to 5) and never values', () => {
    const envContent = [
      '# Database configuration',
      'DATABASE_URL=postgres://user:super_secret_pass_99@db:5432/app',
      'API_KEY=sk_live_1234567890abcdef',
      'export PORT=3000',
      'JWT_SECRET=super_secret_jwt_val',
      'REDIS_PASSWORD=another_secret_pass',
      'EXTRA_VAR=extra_secret',
      'ANOTHER_VAR=final_secret',
    ].join('\n');

    const detail = inspectExposedEnvBody(envContent, 'text/plain');
    assert.ok(detail);
    assert.equal(
      detail,
      'Server exposes /.env (variables: DATABASE_URL, API_KEY, PORT, JWT_SECRET, REDIS_PASSWORD and 2 more)',
    );

    // Verify ZERO secret values appear in the detail string
    assert.ok(!detail.includes('super_secret_pass_99'));
    assert.ok(!detail.includes('sk_live_1234567890abcdef'));
    assert.ok(!detail.includes('super_secret_jwt_val'));
    assert.ok(!detail.includes('another_secret_pass'));
    assert.ok(!detail.includes('extra_secret'));
    assert.ok(!detail.includes('final_secret'));
  });

  it('unit: ENV_FILE_PATHS contains the 4 expected sensitive env files', () => {
    assert.deepEqual(ENV_FILE_PATHS, [
      '/.env',
      '/.env.local',
      '/.env.production',
      '/.env.development',
    ]);
  });

  it('unit: inspectExposedEnvBody supports custom path (e.g. /.env.local, /.env.production)', () => {
    const envContent = 'SECRET_TOKEN=xyz123\nFOO=bar\n';
    const detailLocal = inspectExposedEnvBody(envContent, 'text/plain', '/.env.local');
    assert.equal(detailLocal, 'Server exposes /.env.local (variables: SECRET_TOKEN, FOO)');
    const detailProd = inspectExposedEnvBody(envContent, 'text/plain', '/.env.production');
    assert.equal(detailProd, 'Server exposes /.env.production (variables: SECRET_TOKEN, FOO)');
  });

  it('unit: inspectExposedEnvBody ignores empty file, comments-only, and HTML content', () => {
    assert.equal(inspectExposedEnvBody('', 'text/plain'), null);
    assert.equal(inspectExposedEnvBody('   \n\n  ', 'text/plain'), null);
    assert.equal(inspectExposedEnvBody('# Only comments\n# Second line', 'text/plain'), null);
    assert.equal(
      inspectExposedEnvBody('<!DOCTYPE html><html><body><h1>Not env</h1></body></html>', 'text/html'),
      null,
    );
    assert.equal(
      inspectExposedEnvBody('<div id="root">FOO=bar</div>', 'text/plain'),
      null,
    );
    assert.equal(
      inspectExposedEnvBody('FOO=bar\nBAZ=qux', 'text/html'),
      null,
    );
    assert.equal(
      inspectExposedEnvBody('function main() { const x = 1; }', 'application/javascript'),
      null,
    );
  });

  it('unit: inspectExposedGitConfigBody detects [core] and ignores HTML/non-git files', () => {
    const gitConfig = [
      '[core]',
      '\trepositoryformatversion = 0',
      '\tfilemode = false',
      '\tbare = false',
      '[remote "origin"]',
      '\turl = https://token12345@github.com/org/repo.git',
    ].join('\n');

    assert.equal(inspectExposedGitConfigBody(gitConfig, 'text/plain'), true);
    assert.equal(inspectExposedGitConfigBody('', 'text/plain'), false);
    assert.equal(inspectExposedGitConfigBody('<!DOCTYPE html><html>[core]</html>', 'text/html'), false);
    assert.equal(inspectExposedGitConfigBody('<html [core]>', 'text/plain'), false);
    assert.equal(inspectExposedGitConfigBody('[other_section]\nfoo = bar', 'text/plain'), false);
  });

  it('detects exposed /.env on server exposing project root; ZERO secret values appear in output', async () => {
    const envPayload = [
      '# Super sensitive config',
      'STRIPE_SECRET=sk_live_verysecret1234567890',
      'DATABASE_PASSWORD=SuperSecretDbPassword123!',
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      'API_TOKEN=secret_token_value_abc',
    ].join('\n');

    const server = await startServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><body><h1>Welcome</h1></body></html>');
      } else if (req.url === '/.env') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(envPayload);
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    });

    try {
      const result = await runVibesane({ port: server.port });
      assert.equal(result.ok, false);
      const exposedIssues = result.issues.filter((i) => i.kind === 'exposed_file');
      assert.equal(exposedIssues.length, 1);
      assert.equal(exposedIssues[0].route, '/.env');
      assert.equal(exposedIssues[0].severity, 'error');
      assert.equal(
        exposedIssues[0].detail,
        'Server exposes /.env (variables: STRIPE_SECRET, DATABASE_PASSWORD, AWS_SECRET_ACCESS_KEY, API_TOKEN)',
      );
      assert.equal(exposedIssues[0].maskedSnippet, undefined);
      assert.equal(exposedIssues[0].codeFrame, undefined);

      // Verify that the entire output message and AI prompt contain ZERO values
      const fullOutput = `${result.message}\n${result.aiPrompt ?? ''}`;
      assert.ok(!fullOutput.includes('sk_live_verysecret1234567890'));
      assert.ok(!fullOutput.includes('SuperSecretDbPassword123!'));
      assert.ok(!fullOutput.includes('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'));
      assert.ok(!fullOutput.includes('secret_token_value_abc'));

      // Verify coverage line count remains 1 page (does not count /.env)
      assert.match(result.message, /info: checked 1 page, 0 scripts/);

      // Verify AI prompt has single instruction
      assert.ok(result.aiPrompt?.includes(`Instruction: ${EXPOSED_FILE_INSTRUCTION}`));
    } finally {
      await server.close();
    }
  });

  it('detects exposed /.git/config and never leaks remote URL or tokens', async () => {
    const gitConfigPayload = [
      '[core]',
      '\trepositoryformatversion = 0',
      '\tfilemode = true',
      '[remote "origin"]',
      '\turl = https://ghp_superSecretToken1234567890@github.com/myorg/myrepo.git',
    ].join('\n');

    const server = await startServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><body><h1>App</h1></body></html>');
      } else if (req.url === '/.git/config') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(gitConfigPayload);
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    });

    try {
      const result = await runVibesane({ port: server.port });
      assert.equal(result.ok, false);
      const exposed = result.issues.find((i) => i.route === '/.git/config');
      assert.ok(exposed);
      assert.equal(exposed.kind, 'exposed_file');
      assert.equal(
        exposed.detail,
        'Server exposes /.git/config (the git history may be downloadable)',
      );
      assert.equal(exposed.maskedSnippet, undefined);
      assert.equal(exposed.codeFrame, undefined);

      // Remote token and URL must NEVER appear
      const fullOutput = `${result.message}\n${result.aiPrompt ?? ''}`;
      assert.ok(!fullOutput.includes('ghp_superSecretToken1234567890'));
      assert.ok(!fullOutput.includes('myrepo.git'));
    } finally {
      await server.close();
    }
  });

  it('SPA fallback (200 with index.html for all routes): /.env and /.git/config are completely clean', async () => {
    const spaHtml = '<!DOCTYPE html><html><head><title>SPA</title></head><body><div id="root"></div></body></html>';

    const server = await startServer((req, res) => {
      // Common SPA behavior: every route returns 200 with index.html
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(spaHtml);
    });

    try {
      const result = await runVibesane({ port: server.port });
      assert.equal(result.ok, true);
      assert.equal(result.issues.filter((i) => i.kind === 'exposed_file').length, 0);
      assert.equal(result.issues.filter((i) => i.kind === 'truncated_body').length, 0);
      assert.match(result.message, /info: checked 1 page, 0 scripts/);
    } finally {
      await server.close();
    }
  });

  it('negative: server responding 200 text/html (SPA fallback) for /.env.local and /.env.production emits zero issues and exit code 0', async () => {
    const spaHtml = '<!DOCTYPE html><html><head><title>SPA</title></head><body><div id="app">SPA fallback content</div></body></html>';

    const server = await startServer((req, res) => {
      // SPA fallback responding 200 text/html for /.env.local, /.env.production and all other routes
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(spaHtml);
    });

    try {
      const result = await runVibesane({ port: server.port });
      assert.equal(result.ok, true);
      assert.equal(result.issues.filter((i) => i.kind === 'exposed_file').length, 0);
      assert.equal(result.issues.filter((i) => i.severity === 'error').length, 0);
      assert.equal(result.aiPrompt, null);
      assert.match(result.message, /info: checked 1 page, 0 scripts/);

      // Confirm no variable names or spurious exposed text appear
      const fullOutput = `${result.message}\n${result.aiPrompt ?? ''}`;
      assert.ok(!fullOutput.includes('Server exposes'));
      assert.ok(!fullOutput.includes('variables:'));
    } finally {
      await server.close();
    }
  });

  it('detects exposed /.env.local and /.env.production and verifies ZERO secret values appear in report or AI prompt', async () => {
    const envLocalPayload = [
      '# Local overrides',
      'NEXT_PUBLIC_API_URL=https://api.example.com',
      'SECRET_KEY=sk_live_verysecretlocal999',
    ].join('\n');
    const envProdPayload = [
      '# Production secrets',
      'DATABASE_URL=postgres://prod_user:SuperSecretProdPass123@prod-db:5432/db',
    ].join('\n');

    const server = await startServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><body><h1>Safe App</h1></body></html>');
      } else if (req.url === '/.env.local') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(envLocalPayload);
      } else if (req.url === '/.env.production') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(envProdPayload);
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    });

    try {
      const result = await runVibesane({ port: server.port });
      assert.equal(result.ok, false);
      const exposed = result.issues.filter((i) => i.kind === 'exposed_file');
      assert.equal(exposed.length, 2);

      const localIssue = exposed.find((i) => i.route === '/.env.local');
      assert.ok(localIssue);
      assert.equal(localIssue.severity, 'error');
      assert.equal(
        localIssue.detail,
        'Server exposes /.env.local (variables: NEXT_PUBLIC_API_URL, SECRET_KEY)',
      );

      const prodIssue = exposed.find((i) => i.route === '/.env.production');
      assert.ok(prodIssue);
      assert.equal(prodIssue.severity, 'error');
      assert.equal(
        prodIssue.detail,
        'Server exposes /.env.production (variables: DATABASE_URL)',
      );

      // ZERO secret values appear in message or AI fix prompt
      const fullOutput = `${result.message}\n${result.aiPrompt ?? ''}`;
      assert.ok(!fullOutput.includes('sk_live_verysecretlocal999'));
      assert.ok(!fullOutput.includes('SuperSecretProdPass123'));
      assert.ok(!fullOutput.includes('prod_user'));
      assert.ok(result.aiPrompt?.includes(EXPOSED_FILE_INSTRUCTION));
    } finally {
      await server.close();
    }
  });

  it('403 and 404 responses for /.env and /.git/config are clean (Vite / Next.js behavior)', async () => {
    const server = await startServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><body><h1>Safe App</h1></body></html>');
      } else if (req.url === '/.env') {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
      } else if (req.url === '/.git/config') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    });

    try {
      const result = await runVibesane({ port: server.port });
      assert.equal(result.ok, true);
      assert.equal(result.issues.filter((i) => i.kind === 'exposed_file').length, 0);
      assert.equal(result.issues.filter((i) => i.kind === 'http_error').length, 0);
      assert.equal(result.issues.filter((i) => i.kind === 'slow_route').length, 0);
    } finally {
      await server.close();
    }
  });

  it('302 redirect on /.env to /login does not follow redirect and is clean', async () => {
    const server = await startServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><body><h1>Home</h1></body></html>');
      } else if (req.url === '/.env') {
        res.writeHead(302, { Location: '/login' });
        res.end();
      } else if (req.url === '/login') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><body><h1>Login</h1></body></html>');
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    try {
      const result = await runVibesane({ port: server.port });
      assert.equal(result.ok, true);
      assert.equal(result.issues.filter((i) => i.kind === 'exposed_file').length, 0);
    } finally {
      await server.close();
    }
  });

  it('slow or timing out /.env request fails silently without slow_route or truncated_body', async () => {
    const server = await startServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><body><h1>Root</h1></body></html>');
      } else if (req.url === '/.env') {
        // Hang indefinitely
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    try {
      const result = await runVibesane({
        port: server.port,
        routeTimeoutMs: 150,
        scanBudgetMs: 400,
      });
      assert.equal(result.ok, true);
      assert.equal(result.issues.filter((i) => i.kind === 'slow_route').length, 0);
      assert.equal(result.issues.filter((i) => i.kind === 'http_error').length, 0);
      assert.equal(result.issues.filter((i) => i.kind === 'truncated_body').length, 0);
      assert.equal(result.issues.filter((i) => i.kind === 'exposed_file').length, 0);
    } finally {
      await server.close();
    }
  });

  it('route returning application/octet-stream binary with fake key is ignored (equal to 0.1.5); /.env as octet-stream is detected', async () => {
    const fakeKey = ['sk_live_', '1234567890abcdef1234'].join('');
    const server = await startServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><body><a href="/download.bin">Download</a></body></html>');
      } else if (req.url === '/download.bin') {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        // Binary content containing fake key pattern
        res.end(Buffer.from(`\x00\x01\x02 ${fakeKey} \x03\x04`));
      } else if (req.url === '/.env') {
        // Express / Python style: served as octet-stream
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        res.end('DATABASE_URL=postgres://user:pass@db:5432/app\nPORT=3000\n');
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    });

    try {
      const result = await runVibesane({ port: server.port });
      // download.bin MUST NOT trigger secret_leak
      const secretLeaks = result.issues.filter((i) => i.kind === 'secret_leak');
      assert.equal(secretLeaks.length, 0, 'Binary download must not trigger secret_leak');

      // /.env MUST be detected
      const exposed = result.issues.filter((i) => i.kind === 'exposed_file');
      assert.equal(exposed.length, 1);
      assert.equal(exposed[0].route, '/.env');
      assert.equal(
        exposed[0].detail,
        'Server exposes /.env (variables: DATABASE_URL, PORT)',
      );
    } finally {
      await server.close();
    }
  });
});

describe('AI FIX PROMPT Instruction formatting (1 vs multiple categories) — v0.1.6', () => {
  it('single category (exposed_file only) outputs "Instruction: <EXPOSED_FILE_INSTRUCTION>"', () => {
    const prompt = generateAiFixPrompt({
      ok: false,
      port: 3000,
      url: 'http://localhost:3000',
      issues: [
        {
          kind: 'exposed_file',
          severity: 'error',
          route: '/.env',
          detail: 'Server exposes /.env (variables: A, B)',
        },
      ],
    });

    assert.ok(prompt);
    assert.ok(prompt.includes(`Instruction: ${EXPOSED_FILE_INSTRUCTION}`));
    assert.ok(!prompt.includes('Instruction ('));
  });

  it('preserves 100% exact v0.1.5 output for secrets + code (not a single comma or letter changed)', () => {
    const prompt = generateAiFixPrompt({
      ok: false,
      port: 3000,
      url: 'http://localhost:3000',
      issues: [
        {
          kind: 'secret_leak',
          severity: 'error',
          route: '/src/api.ts',
          detail: 'Secret leak on /src/api.ts: Stripe secret key (sk_live_****1234)',
        },
        {
          kind: 'http_error',
          severity: 'error',
          route: '/broken',
          detail: 'HTTP 500 on route /broken',
        },
      ],
    });

    assert.ok(prompt);
    const lines = prompt.split('\n');
    const secretInstr = lines.find((l) => l.startsWith('Instruction (secrets):'));
    const codeInstr = lines.find((l) => l.startsWith('Instruction (code):'));
    assert.equal(secretInstr, `Instruction (secrets): ${SECRET_LEAK_INSTRUCTION}`);
    assert.equal(codeInstr, `Instruction (code): ${CODE_ERROR_INSTRUCTION}`);
    assert.ok(!prompt.includes('Instruction (exposed files)'));
  });

  it('multiple categories with exposed_file formats strictly in order: secrets, exposed files, code', () => {
    const prompt = generateAiFixPrompt({
      ok: false,
      port: 3000,
      url: 'http://localhost:3000',
      issues: [
        {
          kind: 'http_error',
          severity: 'error',
          route: '/broken',
          detail: 'HTTP 500 on route /broken',
        },
        {
          kind: 'exposed_file',
          severity: 'error',
          route: '/.env',
          detail: 'Server exposes /.env (variables: FOO)',
        },
        {
          kind: 'secret_leak',
          severity: 'error',
          route: '/src/app.ts',
          detail: 'Secret leak on /src/app.ts: Supabase secret key (sb_secret_****1234)',
        },
      ],
    });

    assert.ok(prompt);
    const lines = prompt.split('\n');
    const sIdx = lines.findIndex((l) => l.startsWith('Instruction (secrets):'));
    const eIdx = lines.findIndex((l) => l.startsWith('Instruction (exposed files):'));
    const cIdx = lines.findIndex((l) => l.startsWith('Instruction (code):'));

    assert.ok(sIdx !== -1, 'Must include Instruction (secrets)');
    assert.ok(eIdx !== -1, 'Must include Instruction (exposed files)');
    assert.ok(cIdx !== -1, 'Must include Instruction (code)');

    assert.ok(sIdx < eIdx, 'secrets must come before exposed files');
    assert.ok(eIdx < cIdx, 'exposed files must come before code');

    assert.equal(lines[sIdx], `Instruction (secrets): ${SECRET_LEAK_INSTRUCTION}`);
    assert.equal(lines[eIdx], `Instruction (exposed files): ${EXPOSED_FILE_INSTRUCTION}`);
    assert.equal(lines[cIdx], `Instruction (code): ${CODE_ERROR_INSTRUCTION}`);
  });
});
