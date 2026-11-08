import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  detectInsecureFormMethod,
  METHOD_GET_RE,
  TYPE_PASSWORD_RE,
} from '../dist/rules/insecure-form.js';
import { main } from '../dist/cli.js';

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

test('detectInsecureFormMethod: detects basic method=get with password input', () => {
  const html = '<form method="get"><input type="password"></form>';
  const issues = detectInsecureFormMethod(html, '/login');
  assert.equal(issues.length, 1);
  assert.equal(issues[0].kind, 'insecure_form_method');
  assert.equal(issues[0].severity, 'error');
  assert.equal(issues[0].route, '/login');
  assert.match(issues[0].detail, /sends a password field with method=get/);
  assert.equal(issues[0].maskedSnippet, '<form method="get">');
});

test('detectInsecureFormMethod: handles case-insensitivity (METHOD=GET and TYPE=PASSWORD)', () => {
  const html = '<FORM METHOD="GET" ACTION="/auth"><INPUT TYPE="PASSWORD" NAME="PW"></FORM>';
  const issues = detectInsecureFormMethod(html, '/');
  assert.equal(issues.length, 1);
  assert.equal(issues[0].kind, 'insecure_form_method');
  assert.equal(issues[0].maskedSnippet, '<FORM METHOD="GET" ACTION="/auth">');
});

test('detectInsecureFormMethod: detects single quotes method=\'get\' and type=\'password\'', () => {
  const html = "<form method='get' class='login'><input type='password'/></form>";
  const issues = detectInsecureFormMethod(html, '/auth');
  assert.equal(issues.length, 1);
  assert.equal(issues[0].maskedSnippet, "<form method='get' class='login'>");
});

test('detectInsecureFormMethod: detects unquoted method=get and type=password', () => {
  const html = '<form method=get id=f><input type=password name=p></form>';
  const issues = detectInsecureFormMethod(html, '/login');
  assert.equal(issues.length, 1);
  assert.equal(issues[0].maskedSnippet, '<form method=get id=f>');
});

test('detectInsecureFormMethod: detects multiline attributes with other inputs', () => {
  const html = `
    <form
      id="login-form"
      class="card shadow"
      method="get"
      action="/api/login"
    >
      <label>User</label>
      <input type="text" name="user">
      <label>Pass</label>
      <input name="pass" type="password">
      <button type="submit">Submit</button>
    </form>
  `;
  const issues = detectInsecureFormMethod(html, '/login');
  assert.equal(issues.length, 1);
  assert.match(issues[0].maskedSnippet, /<form[\s\S]*method="get"[\s\S]*>/);
});

test('detectInsecureFormMethod: detects multiple insecure forms on the same page', () => {
  const html = `
    <div>
      <form id="f1" method="get">
        <input type="password" name="p1">
      </form>
      <form id="f2" method="get">
        <input type="password" name="p2">
      </form>
    </div>
  `;
  const issues = detectInsecureFormMethod(html, '/multiple');
  assert.equal(issues.length, 2);
  assert.equal(issues[0].maskedSnippet, '<form id="f1" method="get">');
  assert.equal(issues[1].maskedSnippet, '<form id="f2" method="get">');
});

test('detectInsecureFormMethod: detects form without closing </form> (truncated HTML)', () => {
  const html = '<div><form method="get"><input type="password"></div>';
  const issues = detectInsecureFormMethod(html, '/truncated');
  assert.equal(issues.length, 1);
  assert.equal(issues[0].kind, 'insecure_form_method');
});

test('detectInsecureFormMethod: delimits form scope when another <form> starts without closing previous', () => {
  const html = `
    <form method="get">
      <input type="text" name="search">
    <form method="post">
      <input type="password" name="pass">
    </form>
  `;
  // O primeiro form é GET mas não tem password; o segundo form tem password mas é POST.
  const issues = detectInsecureFormMethod(html, '/malformed');
  assert.equal(issues.length, 0);
});

test('detectInsecureFormMethod: truncates long form tag snippet to max 160 chars', () => {
  const longAttrs = ' '.repeat(10) + 'data-extra="' + 'x'.repeat(200) + '"';
  const html = `<form method="get"${longAttrs}><input type="password"></form>`;
  const issues = detectInsecureFormMethod(html, '/long');
  assert.equal(issues.length, 1);
  assert.equal(issues[0].maskedSnippet.length, 160);
  assert.ok(issues[0].maskedSnippet.endsWith('...'));
});

test('detectInsecureFormMethod: ignores form without method attribute (React/Next pattern)', () => {
  const html = '<form action="/submit"><input type="password" name="pass"></form>';
  const issues = detectInsecureFormMethod(html, '/login');
  assert.equal(issues.length, 0);
});

test('detectInsecureFormMethod: ignores method="post" with password', () => {
  const html = '<form method="post" action="/auth"><input type="password"></form>';
  const issues = detectInsecureFormMethod(html, '/login');
  assert.equal(issues.length, 0);
});

test('detectInsecureFormMethod: ignores method="dialog" with password', () => {
  const html = '<form method="dialog"><input type="password"></form>';
  const issues = detectInsecureFormMethod(html, '/modal');
  assert.equal(issues.length, 0);
});

test('detectInsecureFormMethod: ignores method="get" without password field (search form)', () => {
  const html = '<form method="get" action="/search"><input type="search" name="q"></form>';
  const issues = detectInsecureFormMethod(html, '/search');
  assert.equal(issues.length, 0);
});

test('detectInsecureFormMethod: ignores data-method="get" (prevents false positive in Rails UJS)', () => {
  const html = '<form data-method="get"><input type="password"></form>';
  const issues = detectInsecureFormMethod(html, '/rails');
  assert.equal(issues.length, 0);
});

test('detectInsecureFormMethod: ignores data-type="password" on form GET', () => {
  const html = '<form method="get"><input data-type="password" name="custom"></form>';
  const issues = detectInsecureFormMethod(html, '/custom');
  assert.equal(issues.length, 0);
});

test('detectInsecureFormMethod: ignores name="password" when type is text or passwordx', () => {
  const html1 = '<form method="get"><input name="password" type="text"></form>';
  assert.equal(detectInsecureFormMethod(html1, '/test1').length, 0);

  const html2 = '<form method="get"><input type="passwordx"></form>';
  assert.equal(detectInsecureFormMethod(html2, '/test2').length, 0);
});

test('detectInsecureFormMethod: ignores password input outside any form', () => {
  const html = '<div><label>Pass</label><input type="password"></div>';
  const issues = detectInsecureFormMethod(html, '/no-form');
  assert.equal(issues.length, 0);
});

test('detectInsecureFormMethod: ignores form inside HTML comments', () => {
  const html = '<!-- <form method="get"><input type="password"></form> -->';
  const issues = detectInsecureFormMethod(html, '/commented');
  assert.equal(issues.length, 0);
});

test('detectInsecureFormMethod: ignores unclosed HTML comments', () => {
  const html = '<div>Hello</div><!-- <form method="get"><input type="password">';
  const issues = detectInsecureFormMethod(html, '/unclosed-comment');
  assert.equal(issues.length, 0);
});

test('detectInsecureFormMethod: ignores form inside inline <script> tags', () => {
  const html = `
    <html>
      <head>
        <script>
          const template = '<form method="get"><input type="password"></form>';
        </script>
      </head>
      <body><div>Real content</div></body>
    </html>
  `;
  const issues = detectInsecureFormMethod(html, '/script-tag');
  assert.equal(issues.length, 0);
});

test('detectInsecureFormMethod: handles empty or null input gracefully', () => {
  assert.equal(detectInsecureFormMethod('', '/').length, 0);
  assert.equal(detectInsecureFormMethod(null, '/').length, 0);
});

test('E2E integration: SSR page with GET form and password produces error, exit code 1, AI prompt', async () => {
  const pageHtml = `
    <!doctype html>
    <html>
      <head><title>Login</title></head>
      <body>
        <h1>Sign In</h1>
        <form method="get" action="/do-login">
          <input type="text" name="user">
          <input type="password" name="pass">
          <button type="submit">Login</button>
        </form>
      </body>
    </html>
  `;

  const server = await startServer((req, res) => {
    if (req.url === '/' || req.url === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(pageHtml);
      return;
    }
    res.writeHead(404);
    res.end('Not found');
  });

  try {
    const io = createCaptureIO();
    const code = await main(['--port', String(server.port)], io);
    const stdout = io.getStdout();

    assert.equal(code, 1, 'Exit code must be 1 for error [insecure_form_method]');
    assert.match(stdout, /error \[insecure_form_method\]: form on \/ sends a password field with method=get/);
    assert.match(stdout, /AI FIX PROMPT/);
    assert.match(stdout, /\[insecure_form_method\] form on \/ sends a password field with method=get/);
  } finally {
    await server.close();
  }
});

test('E2E integration: page with form without method (React style) produces OK, exit code 0, no insecure_form_method', async () => {
  const pageHtml = `
    <!doctype html>
    <html>
      <head><title>React App</title></head>
      <body>
        <form action="/login">
          <input type="password" name="secret">
          <button type="submit">Log in</button>
        </form>
      </body>
    </html>
  `;

  const server = await startServer((req, res) => {
    if (req.url === '/' || req.url === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(pageHtml);
      return;
    }
    res.writeHead(404);
    res.end('Not found');
  });

  try {
    const io = createCaptureIO();
    const code = await main(['--port', String(server.port)], io);
    const stdout = io.getStdout();

    assert.equal(code, 0, 'Exit code must be 0 when form has no method');
    assert.doesNotMatch(stdout, /insecure_form_method/);
    assert.doesNotMatch(stdout, /AI FIX PROMPT/);
  } finally {
    await server.close();
  }
});

test('performance regression: form method=get followed by 1 MB of malformed <input without > completes in < 500ms', () => {
  const malformedInput = '<input '.repeat(150000); // ~1.05 MB
  const html = `<form method="get">${malformedInput}`;
  const start = Date.now();
  const issues = detectInsecureFormMethod(html, '/perf1');
  const elapsed = Date.now() - start;
  assert.equal(issues.length, 0);
  assert.ok(elapsed < 500, `Execution took ${elapsed}ms (expected < 500ms)`);
});

test('performance regression: 1 MB of malformed <form without > completes in < 500ms', () => {
  const malformedForm = '<form '.repeat(170000); // ~1.02 MB
  const start = Date.now();
  const issues = detectInsecureFormMethod(malformedForm, '/perf2');
  const elapsed = Date.now() - start;
  assert.equal(issues.length, 0);
  assert.ok(elapsed < 500, `Execution took ${elapsed}ms (expected < 500ms)`);
});

test('performance regression: 1 MB of malformed <script without > completes in < 500ms', () => {
  const malformedScript = '<script '.repeat(130000); // ~1.04 MB
  const start = Date.now();
  const issues = detectInsecureFormMethod(malformedScript, '/perf3');
  const elapsed = Date.now() - start;
  assert.equal(issues.length, 0);
  assert.ok(elapsed < 500, `Execution took ${elapsed}ms (expected < 500ms)`);
});

test('performance regression: ~1 MB of valid GET search forms without password completes in < 500ms and yields 0 issues', () => {
  const singleForm = '<form method="get" action="/search"><input type="search" name="q"><button>Search</button></form>\n';
  const html = singleForm.repeat(10500); // ~1.03 MB
  const start = Date.now();
  const issues = detectInsecureFormMethod(html, '/search');
  const elapsed = Date.now() - start;
  assert.equal(issues.length, 0);
  assert.ok(elapsed < 500, `Execution took ${elapsed}ms (expected < 500ms)`);
});
