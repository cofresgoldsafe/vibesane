import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { inspectRootSecurityHeaders } from '../dist/rules/security-headers.js';

describe('rules: security headers (missing_security_headers)', () => {
  it('emite warning quando X-Content-Type-Options: nosniff está ausente', () => {
    const headers = new Map([
      ['x-frame-options', 'SAMEORIGIN'],
    ]);
    const issues = inspectRootSecurityHeaders(headers, '/');
    assert.equal(issues.length, 1);
    assert.equal(issues[0].kind, 'missing_security_headers');
    assert.equal(issues[0].severity, 'warning');
    assert.match(issues[0].detail, /Missing X-Content-Type-Options: nosniff/);
  });

  it('emite warning quando não há proteção contra framing', () => {
    const headers = new Map([
      ['x-content-type-options', 'nosniff'],
    ]);
    const issues = inspectRootSecurityHeaders(headers, '/');
    assert.equal(issues.length, 1);
    assert.equal(issues[0].kind, 'missing_security_headers');
    assert.equal(issues[0].severity, 'warning');
    assert.match(issues[0].detail, /Missing anti-framing protection/);
  });

  it('emite 2 warnings quando ambos estão ausentes', () => {
    const headers = new Map([]);
    const issues = inspectRootSecurityHeaders(headers, '/');
    assert.equal(issues.length, 2);
  });

  it('aprova proteção anti-framing via X-Frame-Options: DENY ou SAMEORIGIN', () => {
    for (const val of ['DENY', 'SAMEORIGIN']) {
      const headers = new Map([
        ['x-content-type-options', 'nosniff'],
        ['x-frame-options', val],
      ]);
      const issues = inspectRootSecurityHeaders(headers, '/');
      assert.equal(issues.length, 0);
    }
  });

  it('aprova proteção anti-framing via CSP frame-ancestors', () => {
    const headers = new Map([
      ['x-content-type-options', 'nosniff'],
      ['content-security-policy', "default-src 'self'; frame-ancestors 'none'"],
    ]);
    const issues = inspectRootSecurityHeaders(headers, '/');
    assert.equal(issues.length, 0);
  });

  it('aceita valores repetidos concatenados com vírgula pelo Headers.get() sem falso positivo', () => {
    const headers = new Map([
      ['x-content-type-options', 'nosniff, nosniff'],
      ['x-frame-options', 'SAMEORIGIN, SAMEORIGIN'],
    ]);
    const issues = inspectRootSecurityHeaders(headers, '/');
    assert.equal(issues.length, 0);

    const headersDeny = new Map([
      ['x-content-type-options', 'nosniff, other'],
      ['x-frame-options', 'DENY, DENY'],
    ]);
    const issuesDeny = inspectRootSecurityHeaders(headersDeny, '/');
    assert.equal(issuesDeny.length, 0);
  });
});
