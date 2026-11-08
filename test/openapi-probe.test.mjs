import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { runVibesane } from '../dist/index.js';
import { extractEligibleOpenApiGetRoutes } from '../dist/scanner/route-crawler.js';

describe('OpenAPI Unauthenticated Routes Probe — v0.1.10', () => {
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

  it('unit: extractEligibleOpenApiGetRoutes handles invalid json or missing paths gracefully', () => {
    assert.deepEqual(extractEligibleOpenApiGetRoutes('', 'http://127.0.0.1:3000'), []);
    assert.deepEqual(extractEligibleOpenApiGetRoutes('{ invalid', 'http://127.0.0.1:3000'), []);
    assert.deepEqual(extractEligibleOpenApiGetRoutes('null', 'http://127.0.0.1:3000'), []);
    assert.deepEqual(extractEligibleOpenApiGetRoutes('{"info": {}}', 'http://127.0.0.1:3000'), []);
  });

  it('unit: extractEligibleOpenApiGetRoutes filters path parameters with {param}', () => {
    const doc = JSON.stringify({
      paths: {
        '/users/{id}': { get: {} },
        '/users/all': { get: {} },
      },
    });
    const routes = extractEligibleOpenApiGetRoutes(doc, 'http://127.0.0.1:3000');
    assert.deepEqual(routes, ['/users/all']);
  });

  it('unit: extractEligibleOpenApiGetRoutes filters parameters with required: true and $ref', () => {
    const doc = JSON.stringify({
      paths: {
        '/search': {
          get: {
            parameters: [{ name: 'q', in: 'query', required: true }],
          },
        },
        '/filter': {
          parameters: [{ $ref: '#/components/parameters/FilterParam' }],
          get: {},
        },
        '/public': {
          get: {
            parameters: [{ name: 'page', in: 'query', required: false }],
          },
        },
      },
    });
    const routes = extractEligibleOpenApiGetRoutes(doc, 'http://127.0.0.1:3000');
    assert.deepEqual(routes, ['/public']);
  });

  it('unit: extractEligibleOpenApiGetRoutes filters action segments', () => {
    const doc = JSON.stringify({
      paths: {
        '/cron/run': { get: {} },
        '/system/shutdown': { get: {} },
        '/data/sync': { get: {} },
        '/auth/logout': { get: {} },
        '/db/migrate': { get: {} },
        '/api/events': { get: {} },
      },
    });
    const routes = extractEligibleOpenApiGetRoutes(doc, 'http://127.0.0.1:3000');
    assert.deepEqual(routes, ['/api/events']);
  });

  it('unit: extractEligibleOpenApiGetRoutes filters reserved documentation and health paths', () => {
    const doc = JSON.stringify({
      paths: {
        '/': { get: {} },
        '/health': { get: {} },
        '/healthz': { get: {} },
        '/docs': { get: {} },
        '/docs/oauth2-redirect': { get: {} },
        '/redoc': { get: {} },
        '/openapi.json': { get: {} },
        '/items': { get: {} },
      },
    });
    const routes = extractEligibleOpenApiGetRoutes(doc, 'http://127.0.0.1:3000');
    assert.deepEqual(routes, ['/items']);
  });

  it('unit: extractEligibleOpenApiGetRoutes prevents host injection and non-local origins', () => {
    const doc = JSON.stringify({
      paths: {
        '//attacker.com/steal': { get: {} },
        'http://evil.com/webhook': { get: {} },
        '/valid/webhook': { get: {} },
      },
    });
    const routes = extractEligibleOpenApiGetRoutes(doc, 'http://127.0.0.1:3000');
    assert.deepEqual(routes, ['/valid/webhook']);
  });

  it('unit: extractEligibleOpenApiGetRoutes caps at MAX_PROBED_API_ROUTES (5 routes)', () => {
    const pathsObj = {};
    for (let i = 1; i <= 8; i++) {
      pathsObj[`/route-${i}`] = { get: {} };
    }
    const doc = JSON.stringify({ paths: pathsObj });
    const routes = extractEligibleOpenApiGetRoutes(doc, 'http://127.0.0.1:3000');
    assert.equal(routes.length, 5);
    assert.deepEqual(routes, ['/route-1', '/route-2', '/route-3', '/route-4', '/route-5']);
  });

  it('integration: probes unauthenticated 200 JSON route, reports warning, and emits info: probed line', async () => {
    const server = await startServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ detail: 'Not Found' }));
        return;
      }
      if (req.url === '/openapi.json') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            paths: {
              '/webhook/events': { get: {} },
            },
          }),
        );
        return;
      }
      if (req.url === '/webhook/events') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ events: [{ id: 1, type: 'deal.updated' }] }));
        return;
      }
      res.writeHead(404);
      res.end();
    });

    try {
      const result = await runVibesane({ port: server.port });
      assert.equal(result.ok, true);
      assert.deepEqual(result.probedApiRoutes, ['/webhook/events']);

      const openApiIssue = result.issues.find((i) => i.kind === 'unauthenticated_api_route');
      assert.ok(openApiIssue, 'expected unauthenticated_api_route warning');
      assert.equal(openApiIssue.severity, 'warning');
      assert.equal(openApiIssue.route, '/webhook/events');
      assert.equal(
        openApiIssue.detail,
        'GET /webhook/events answered 200 JSON without credentials (listed in /openapi.json); if it is not meant to be public, require authentication',
      );

      // Verify that no response body is printed in the message
      assert.ok(!result.message.includes('deal.updated'));

      // Verify message order: coverageLine followed by probedLine
      assert.match(
        result.message,
        /info: checked 1 JSON response[^\r\n]*\r?\ninfo: probed 1 GET route listed in \/openapi\.json/,
      );
    } finally {
      await server.close();
    }
  });

  it('integration: protected route returning 403 counts as probed without raising issues', async () => {
    const server = await startServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ detail: 'Not Found' }));
        return;
      }
      if (req.url === '/openapi.json') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            paths: {
              '/admin/users': { get: {} },
            },
          }),
        );
        return;
      }
      if (req.url === '/admin/users') {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ detail: 'Forbidden' }));
        return;
      }
      res.writeHead(404);
      res.end();
    });

    try {
      const result = await runVibesane({ port: server.port });
      assert.equal(result.ok, true);
      assert.deepEqual(result.probedApiRoutes, ['/admin/users']);

      const unauthIssues = result.issues.filter((i) => i.kind === 'unauthenticated_api_route');
      assert.equal(unauthIssues.length, 0);

      assert.match(result.message, /info: probed 1 GET route listed in \/openapi\.json/);
    } finally {
      await server.close();
    }
  });

  it('integration: scans secrets in unauthenticated 200 JSON responses', async () => {
    // Dynamically assemble secret to avoid hardcoded token in source
    const fakeSecret = ['sk', 'live', '1234567890abcdef'].join('_');

    const server = await startServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ detail: 'Not Found' }));
        return;
      }
      if (req.url === '/openapi.json') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            paths: {
              '/api/config': { get: {} },
            },
          }),
        );
        return;
      }
      if (req.url === '/api/config') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ stripeApiKey: fakeSecret }));
        return;
      }
      res.writeHead(404);
      res.end();
    });

    try {
      const result = await runVibesane({ port: server.port });
      assert.equal(result.ok, false);

      const secretLeak = result.issues.find((i) => i.kind === 'secret_leak');
      assert.ok(secretLeak, 'expected secret_leak error');
      assert.equal(secretLeak.severity, 'error');
      assert.equal(secretLeak.route, '/api/config');
      assert.ok(secretLeak.maskedSnippet?.includes('sk_live_****cdef'));

      const unauthIssue = result.issues.find((i) => i.kind === 'unauthenticated_api_route');
      assert.ok(unauthIssue, 'expected unauthenticated_api_route warning');

      assert.ok(result.aiPrompt, 'expected AI FIX PROMPT on error');
      assert.match(
        result.message,
        /info: probed 1 GET route listed in \/openapi\.json/,
      );
    } finally {
      await server.close();
    }
  });

  it('integration: fails open and silent when /openapi.json is 404 or corrupted', async () => {
    const server = await startServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ detail: 'Not Found' }));
        return;
      }
      if (req.url === '/openapi.json') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{ invalid json doc');
        return;
      }
      res.writeHead(404);
      res.end();
    });

    try {
      const result = await runVibesane({ port: server.port });
      assert.equal(result.ok, true);
      assert.deepEqual(result.probedApiRoutes, []);
      assert.ok(!result.message.includes('probed'));
    } finally {
      await server.close();
    }
  });
});
