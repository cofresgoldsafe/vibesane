import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { detectStackTraceLeak } from '../dist/rules/stack-traces.js';

describe('rules: stack traces (stack_trace_leak)', () => {
  it('teste positivo obrigatório de traceback Python', () => {
    const pyTrace = 'Traceback (most recent call last):\n  File "/app/a.py", line 3, in <module>';
    const issue = detectStackTraceLeak(pyTrace, 500, '/api/py');
    assert.ok(issue);
    assert.equal(issue.kind, 'stack_trace_leak');
    assert.equal(issue.severity, 'error');
    assert.match(issue.detail, /Traceback \(most recent call last\)/);
  });

  it('detecta traceback Python embutido em tags HTML do Werkzeug/Flask e do Django debug', () => {
    const werkzeugHtml = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
  <head><title>Internal Server Error</title></head>
  <body>
    <h1>Internal Server Error</h1>
    <div class="traceback">
      <pre>Traceback (most recent call last):
  File "/srv/app/server.py", line 42, in index
    return 1 / 0
ZeroDivisionError: division by zero</pre>
    </div>
  </body>
</html>`;
    const werkzeugIssue = detectStackTraceLeak(werkzeugHtml, 500, '/flask-error');
    assert.ok(werkzeugIssue, 'expected detection for Werkzeug HTML error');
    assert.equal(werkzeugIssue.kind, 'stack_trace_leak');

    const djangoHtml = `<!DOCTYPE html>
<html lang="en">
<head><title>ZeroDivisionError at /crash</title></head>
<body>
<div id="summary">
  <h1>ZeroDivisionError at /crash</h1>
  <pre class="exception_value">division by zero</pre>
  <table class="meta">
    <tr><th>Python Executable:</th><td>/usr/local/bin/python</td></tr>
  </table>
</div>
<div id="traceback">
  <h2>Traceback</h2>
  <div class="commands"><a href="#" onclick="...">Switch to copy-and-paste view</a></div>
  <pre>Traceback (most recent call last):
  File "/opt/django/core/handlers/exception.py", line 55, in inner
    response = get_response(request)
  File "/opt/django/views.py", line 18, in crash_view
    return 10 / 0</pre>
</div>
</body></html>`;
    const djangoIssue = detectStackTraceLeak(djangoHtml, 500, '/django-error');
    assert.ok(djangoIssue, 'expected detection for Django HTML error');
    assert.equal(djangoIssue.kind, 'stack_trace_leak');
  });

  it('detecta formatos canônicos de stack frame V8', () => {
    const v8Samples = [
      'Error: crash\n    at Object.handler (/var/task/pages/api/login.js:10:5)',
      'TypeError: boom\n    at C:\\app\\server.ts:45:9',
      'Error: worker fail\n    at async run (/app/worker.js:12:3)',
      'Error: db fail\n    at new Query (/app/db.js:1:2)',
      'Error: alias fail\n    at X [as y] (/app/z.js:1:2)',
      'Error: simple\n    at /x.js:1:2',
    ];

    for (const sample of v8Samples) {
      const issue = detectStackTraceLeak(sample, 500, '/api/err');
      assert.ok(issue, `expected detection for sample: ${sample}`);
      assert.equal(issue.kind, 'stack_trace_leak');
      assert.equal(issue.severity, 'error');
    }
  });

  it('detecta erros crus de banco de dados e ORMs (Prisma, PostgreSQL, MySQL, Oracle)', () => {
    const dbSamples = [
      'PrismaClientKnownRequestError: Unique constraint failed on the fields: (`email`)',
      'Invalid `prisma.user.findUnique()` invocation in /app/api.ts:15',
      'syntax error at or near "WHERE" at character 42',
      'relation "app_users" does not exist',
      'column "password_hash" does not exist',
      "Table 'production.orders' doesn't exist",
      'ORA-00942: table or view does not exist',
    ];

    for (const sample of dbSamples) {
      const issue = detectStackTraceLeak(sample, 500, '/api/db');
      assert.ok(issue, `expected detection for DB error: ${sample}`);
      assert.equal(issue.kind, 'stack_trace_leak');
      assert.equal(issue.severity, 'error');
    }
  });

  it('detecta stack traces serializados em JSON com literais \\n', () => {
    const jsonBody = JSON.stringify({
      error: 'Crash',
      stack: 'Error: x\n    at h (/app/s.js:10:5)',
    });
    const issue = detectStackTraceLeak(jsonBody, 500, '/api/json-err');
    assert.ok(issue);
    assert.equal(issue.kind, 'stack_trace_leak');
    assert.equal(issue.severity, 'error');
  });

  it('em respostas com status 200 (páginas de docs/tutoriais), silencia totalmente', () => {
    const sample = 'Tutorial: Como lidar com Traceback (most recent call last):\n  File "/app/a.py", line 3';
    const issue = detectStackTraceLeak(sample, 200, '/docs/python-error');
    assert.equal(issue, null);
  });

  describe('testes de regressão de 1 MB (< 500 ms) sem backtracking catastrófico', () => {
    it('\\nat + 1 MB de espaços executa em < 500 ms', () => {
      const payload = '\nat ' + ' '.repeat(1024 * 1024);
      const start = performance.now();
      detectStackTraceLeak(payload, 500);
      const elapsed = performance.now() - start;
      assert.ok(elapsed < 500, `expected < 500ms, took ${elapsed}ms`);
    });

    it('\\n at x ( repetido executa em < 500 ms', () => {
      const payload = '\n at x ('.repeat(50000);
      const start = performance.now();
      detectStackTraceLeak(payload, 500);
      const elapsed = performance.now() - start;
      assert.ok(elapsed < 500, `expected < 500ms, took ${elapsed}ms`);
    });

    it('\\nat / + 1 MB de "a" executa em < 500 ms', () => {
      const payload = '\nat /' + 'a'.repeat(1024 * 1024);
      const start = performance.now();
      detectStackTraceLeak(payload, 500);
      const elapsed = performance.now() - start;
      assert.ok(elapsed < 500, `expected < 500ms, took ${elapsed}ms`);
    });

    it('\\nat a [as + 1 MB de "b" executa em < 500 ms', () => {
      const payload = '\nat a [as ' + 'b'.repeat(1024 * 1024);
      const start = performance.now();
      detectStackTraceLeak(payload, 500);
      const elapsed = performance.now() - start;
      assert.ok(elapsed < 500, `expected < 500ms, took ${elapsed}ms`);
    });

    it('1 MB de literais \\n repetidos executa em < 500 ms', () => {
      const payload = '\\n'.repeat(500 * 1024);
      const start = performance.now();
      detectStackTraceLeak(payload, 500);
      const elapsed = performance.now() - start;
      assert.ok(elapsed < 500, `expected < 500ms, took ${elapsed}ms`);
    });

    it('Traceback + 1 MB de texto executa em < 500 ms', () => {
      const payload = 'Traceback (most recent call last):\n' + 'x'.repeat(1024 * 1024);
      const start = performance.now();
      detectStackTraceLeak(payload, 500);
      const elapsed = performance.now() - start;
      assert.ok(elapsed < 500, `expected < 500ms, took ${elapsed}ms`);
    });

    it('PrismaClient + 1 MB de texto executa em < 500 ms', () => {
      const payload = 'PrismaClient' + 'x'.repeat(1024 * 1024);
      const start = performance.now();
      detectStackTraceLeak(payload, 500);
      const elapsed = performance.now() - start;
      assert.ok(elapsed < 500, `expected < 500ms, took ${elapsed}ms`);
    });
  });
});
