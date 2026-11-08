import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  isReflectedCredentialedCors,
  CORS_PROBE_ORIGIN,
  CORS_PROBE_PATHS,
  probeCors,
} from '../dist/scanner/cors-probe.js';
import { main } from '../dist/cli.js';
import { generateAiFixPrompt } from '../dist/reporter/ai-prompt-gen.js';

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

test('isReflectedCredentialedCors - unit tests', () => {
  // 1. Igual + credentials 'true' -> true
  const h1 = new Headers({
    'access-control-allow-origin': CORS_PROBE_ORIGIN,
    'access-control-allow-credentials': 'true',
  });
  assert.equal(isReflectedCredentialedCors(h1, CORS_PROBE_ORIGIN), true);

  // 2. Case-insensitive na origem e credentials
  const h2 = new Headers({
    'access-control-allow-origin': CORS_PROBE_ORIGIN.toUpperCase(),
    'access-control-allow-credentials': 'TRUE',
  });
  assert.equal(isReflectedCredentialedCors(h2, CORS_PROBE_ORIGIN), true);

  // 3. Origem diferente -> false
  const h3 = new Headers({
    'access-control-allow-origin': 'http://localhost:3000',
    'access-control-allow-credentials': 'true',
  });
  assert.equal(isReflectedCredentialedCors(h3, CORS_PROBE_ORIGIN), false);

  // 4. Credentials ausente ou 'false' -> false
  const h4 = new Headers({
    'access-control-allow-origin': CORS_PROBE_ORIGIN,
  });
  assert.equal(isReflectedCredentialedCors(h4, CORS_PROBE_ORIGIN), false);

  const h5 = new Headers({
    'access-control-allow-origin': CORS_PROBE_ORIGIN,
    'access-control-allow-credentials': 'false',
  });
  assert.equal(isReflectedCredentialedCors(h5, CORS_PROBE_ORIGIN), false);

  // 5. * com credentials 'true' -> false (pois * !== probeOrigin)
  const h6 = new Headers({
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true',
  });
  assert.equal(isReflectedCredentialedCors(h6, CORS_PROBE_ORIGIN), false);

  // 6. * sem credentials -> false
  const h7 = new Headers({
    'access-control-allow-origin': '*',
  });
  assert.equal(isReflectedCredentialedCors(h7, CORS_PROBE_ORIGIN), false);
});

test('CLI: flags insecure_cors when server mirrors Origin with credentials', async () => {
  const srv = await startServer((req, res) => {
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>App</h1></body></html>');
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 1);
    const out = io.getStdout();
    assert.match(out, /error \[insecure_cors\]/);
    assert.match(out, /Server reflects any Origin with credentials allowed on \//);
    assert.match(out, /Instruction: Do not reflect the request Origin when credentials are allowed/);
  } finally {
    await srv.close();
  }
});

test('CLI: clean when Access-Control-Allow-Origin is * without credentials', async () => {
  const srv = await startServer((_req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>Safe API</h1></body></html>');
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 0);
    const out = io.getStdout();
    assert.doesNotMatch(out, /insecure_cors/);
  } finally {
    await srv.close();
  }
});

test('CLI: clean when Access-Control-Allow-Origin is * with credentials: true', async () => {
  const srv = await startServer((_req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>Ignored by Browser</h1></body></html>');
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 0);
    const out = io.getStdout();
    assert.doesNotMatch(out, /insecure_cors/);
  } finally {
    await srv.close();
  }
});

test('CLI: clean when server has a fixed allowlist with credentials', async () => {
  const srv = await startServer((_req, res) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>Trusted Origin</h1></body></html>');
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 0);
    const out = io.getStdout();
    assert.doesNotMatch(out, /insecure_cors/);
  } finally {
    await srv.close();
  }
});

test('CLI: detects Starlette style (mirrors Origin only when cookie is present)', async () => {
  const srv = await startServer((req, res) => {
    const origin = req.headers.origin;
    const cookie = req.headers.cookie;
    // Starlette / FastAPI CORSMiddleware logic: só espelha com allow_origins=['*'] se houver cookie
    if (origin && cookie && cookie.includes('vibesane_cors_probe=1')) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>FastAPI App</h1></body></html>');
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 1);
    const out = io.getStdout();
    assert.match(out, /error \[insecure_cors\]/);
  } finally {
    await srv.close();
  }
});

test('CLI: detects insecure CORS isolated to /api route', async () => {
  const srv = await startServer((req, res) => {
    if (req.url === '/api') {
      const origin = req.headers.origin;
      if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"status":"ok"}');
      return;
    }
    // Raiz normal sem CORS
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>App</h1></body></html>');
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 1);
    const out = io.getStdout();
    assert.match(out, /error \[insecure_cors\]: Server reflects any Origin with credentials allowed on \/api/);
  } finally {
    await srv.close();
  }
});

test('CLI: clean when Origin is mirrored WITHOUT credentials allowed', async () => {
  const srv = await startServer((req, res) => {
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      // Sem Access-Control-Allow-Credentials
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>No credentials</h1></body></html>');
  });

  const io = createCaptureIO();
  try {
    const code = await main(['--port', String(srv.port)], io);
    assert.equal(code, 0);
    const out = io.getStdout();
    assert.doesNotMatch(out, /insecure_cors/);
  } finally {
    await srv.close();
  }
});

test('probeCors: fails open and silent on route timeout without slow_route', async () => {
  const srv = await startServer((req, res) => {
    // Dorme se for a sonda
    if (req.headers.origin === CORS_PROBE_ORIGIN) {
      // Deixa pendente sem responder para forçar timeout
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>Ok</h1></body></html>');
  });

  try {
    const controller = new AbortController();
    const issues = await probeCors(`http://127.0.0.1:${srv.port}`, controller.signal, 50);
    assert.deepEqual(issues, []);
  } finally {
    await srv.close();
  }
});

test('AI FIX PROMPT formatting: cors alone and cors + secrets ordered', () => {
  // Caso 1: Apenas insecure_cors
  const promptAlone = generateAiFixPrompt({
    ok: false,
    port: 3000,
    url: 'http://localhost:3000',
    issues: [
      {
        kind: 'insecure_cors',
        severity: 'error',
        route: '/',
        detail: 'Server reflects any Origin with credentials allowed on /',
      },
    ],
  });
  assert.ok(promptAlone);
  assert.match(promptAlone, /^Instruction: Do not reflect the request Origin when credentials are allowed/m);

  // Caso 2: insecure_cors + secret_leak -> ordem secrets, cors
  const promptMulti = generateAiFixPrompt({
    ok: false,
    port: 3000,
    url: 'http://localhost:3000',
    issues: [
      {
        kind: 'insecure_cors',
        severity: 'error',
        route: '/',
        detail: 'Server reflects any Origin with credentials allowed on /',
      },
      {
        kind: 'secret_leak',
        severity: 'error',
        route: '/src/main.js',
        detail: 'Secret leak on /src/main.js: Stripe secret key (sk_live_****)',
      },
    ],
  });
  assert.ok(promptMulti);
  const secretsIdx = promptMulti.indexOf('Instruction (secrets):');
  const corsIdx = promptMulti.indexOf('Instruction (cors):');
  assert.ok(secretsIdx !== -1, 'Must contain Instruction (secrets)');
  assert.ok(corsIdx !== -1, 'Must contain Instruction (cors)');
  assert.ok(secretsIdx < corsIdx, 'Instruction (secrets) must precede Instruction (cors)');
});

test('Normal crawler requests DO NOT send Origin header', async () => {
  const nonProbeOrigins = [];
  const srv = await startServer((req, res) => {
    const origin = req.headers.origin;
    const cookie = req.headers.cookie;
    const isProbe = origin === CORS_PROBE_ORIGIN || (cookie && cookie.includes('vibesane_cors_probe=1'));
    if (!isProbe) {
      nonProbeOrigins.push(origin);
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><a href="/about">About</a></body></html>');
  });

  const io = createCaptureIO();
  try {
    await main(['--port', String(srv.port)], io);
    // As requisições do crawler normal não devem ter origin
    assert.ok(nonProbeOrigins.length > 0, 'Crawler must have made regular requests');
    for (const org of nonProbeOrigins) {
      assert.equal(org, undefined, `Regular request sent unexpected Origin: ${org}`);
    }
  } finally {
    await srv.close();
  }
});
