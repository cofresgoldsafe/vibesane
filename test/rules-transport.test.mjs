import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  isTlsErrorCode,
  inspectTlsError,
  inspectHttpRedirect,
  inspectHstsHeader,
} from '../dist/rules/transport.js';

describe('rules: transport (insecure_transport)', () => {
  describe('isTlsErrorCode', () => {
    it('reconhece códigos canônicos de falha TLS', () => {
      const canonicalCodes = [
        'CERT_HAS_EXPIRED',
        'DEPTH_ZERO_SELF_SIGNED_CERT',
        'SELF_SIGNED_CERT_IN_CHAIN',
        'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        'ERR_TLS_CERT_ALTNAME_INVALID',
      ];
      for (const code of canonicalCodes) {
        assert.equal(isTlsErrorCode(code), true, `expected ${code} to be TLS code`);
      }
    });

    it('reconhece prefixos CERT_ e ERR_TLS_', () => {
      assert.equal(isTlsErrorCode('CERT_REVOKED'), true);
      assert.equal(isTlsErrorCode('ERR_TLS_PROTOCOL_VERSION'), true);
      assert.equal(isTlsErrorCode('ERR_TLS_HANDSHAKE_TIMEOUT'), true);
    });

    it('rejeita erros de rede comuns que não são TLS', () => {
      const nonTls = ['ENOTFOUND', 'ECONNREFUSED', 'ETIMEDOUT', 'EAI_AGAIN', undefined, ''];
      for (const code of nonTls) {
        assert.equal(isTlsErrorCode(code), false, `expected ${code} not to be TLS code`);
      }
    });
  });

  describe('inspectTlsError', () => {
    it('gera issue error com o código TLS exato', () => {
      const issue = inspectTlsError('CERT_HAS_EXPIRED', '/');
      assert.equal(issue.kind, 'insecure_transport');
      assert.equal(issue.severity, 'error');
      assert.equal(
        issue.detail,
        'TLS connection failed: certificate verification failed (CERT_HAS_EXPIRED)',
      );
    });
  });

  describe('inspectHttpRedirect', () => {
    it('aceita redirecionamento 301/308 para https do mesmo host', () => {
      const res301 = inspectHttpRedirect(301, 'https://meusite.com/', 'meusite.com');
      assert.equal(res301.ok, true);
      assert.equal(res301.issue, undefined);

      const res308 = inspectHttpRedirect(308, 'https://meusite.com/app', 'meusite.com');
      assert.equal(res308.ok, true);
    });

    it('aceita redirecionamento para o mesmo domínio com www', () => {
      const toWww = inspectHttpRedirect(301, 'https://www.meusite.com/', 'meusite.com');
      assert.equal(toWww.ok, true);

      const fromWww = inspectHttpRedirect(302, 'https://meusite.com/', 'www.meusite.com');
      assert.equal(fromWww.ok, true);
    });

    it('silencia quando HTTP responde com status 4xx ou 5xx (ex: 400, 403, 426)', () => {
      for (const status of [400, 403, 404, 426, 500, 502]) {
        const outcome = inspectHttpRedirect(status, undefined, 'meusite.com');
        assert.equal(outcome.ok, true, `expected silence for HTTP status ${status}`);
        assert.equal(outcome.issue, undefined);
      }
    });

    it('emite error quando HTTP responde 200 direto sem redirect', () => {
      const outcome = inspectHttpRedirect(200, undefined, 'meusite.com');
      assert.equal(outcome.ok, false);
      assert.equal(outcome.issue?.kind, 'insecure_transport');
      assert.equal(outcome.issue?.severity, 'error');
      assert.equal(
        outcome.issue?.detail,
        'Site serves content over unencrypted HTTP and does not redirect to HTTPS',
      );
    });

    it('emite error quando redireciona para host externo', () => {
      const outcome = inspectHttpRedirect(301, 'https://evil.com/', 'meusite.com');
      assert.equal(outcome.ok, false);
      assert.equal(outcome.issue?.kind, 'insecure_transport');
      assert.equal(outcome.issue?.severity, 'error');
    });
  });

  describe('inspectHstsHeader', () => {
    it('emite warning quando HSTS está ausente', () => {
      const outcome = inspectHstsHeader(null);
      assert.equal(outcome.ok, false);
      assert.equal(outcome.issue?.kind, 'insecure_transport');
      assert.equal(outcome.issue?.severity, 'warning');
      assert.match(outcome.issue?.detail ?? '', /Strict-Transport-Security \(HSTS\) header is missing/);
    });

    it('emite warning quando max-age é 0', () => {
      const outcome = inspectHstsHeader('max-age=0');
      assert.equal(outcome.ok, false);
      assert.equal(outcome.issue?.severity, 'warning');
    });

    it('aprova quando max-age é positivo', () => {
      const outcome = inspectHstsHeader('max-age=31536000; includeSubDomains; preload');
      assert.equal(outcome.ok, true);
      assert.equal(outcome.issue, undefined);
    });
  });
});
