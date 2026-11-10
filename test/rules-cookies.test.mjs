import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isSessionCookieName, parseSetCookieHeader, inspectSetCookie } from '../dist/rules/cookies.js';

describe('rules: cookies (insecure_cookie)', () => {
  describe('isSessionCookieName - Exclusão de CSRF/XSRF', () => {
    it('exclui sumariamente XSRF-TOKEN, csrf_token, _csrf e csrftoken mesmo contendo "token"', () => {
      assert.equal(isSessionCookieName('XSRF-TOKEN'), false);
      assert.equal(isSessionCookieName('csrf_token'), false);
      assert.equal(isSessionCookieName('_csrf'), false);
      assert.equal(isSessionCookieName('csrftoken'), false);
      assert.equal(isSessionCookieName('anti-csrf-token'), false);
    });

    it('exclui cookies conhecidos de analytics e preferências de UI', () => {
      const nonSession = [
        '_ga',
        '_gid',
        '_gat',
        '_fbp',
        '_clck',
        'theme',
        'dark_mode',
        'color_mode',
        'cookie_consent',
      ];
      for (const name of nonSession) {
        assert.equal(isSessionCookieName(name), false, `expected ${name} not to be session cookie`);
      }
    });

    it('isola casamento por tokens delimitados (evita casar com substring)', () => {
      // "sid" NÃO pode casar com sidebar_state, consider ou insider
      assert.equal(isSessionCookieName('sidebar_state'), false);
      assert.equal(isSessionCookieName('consider'), false);
      assert.equal(isSessionCookieName('insider'), false);
      assert.equal(isSessionCookieName('residential'), false);
    });

    it('reconhece nomes e tokens legítimos de sessão', () => {
      assert.equal(isSessionCookieName('sid'), true);
      assert.equal(isSessionCookieName('app_sid'), true);
      assert.equal(isSessionCookieName('user_session'), true);
      assert.equal(isSessionCookieName('auth_token'), true);
      assert.equal(isSessionCookieName('access_token'), true);
      assert.equal(isSessionCookieName('refresh_token'), true);
      assert.equal(isSessionCookieName('connect.sid'), true);
      assert.equal(isSessionCookieName('phpsessid'), true);
      assert.equal(isSessionCookieName('next-auth.session-token'), true);
      assert.equal(isSessionCookieName('sb-xyz-auth-token'), true);
    });
  });

  describe('parseSetCookieHeader', () => {
    it('extrai corretamente atributos Secure, HttpOnly e SameSite', () => {
      const parsed = parseSetCookieHeader(
        'session_id=12345; Path=/; Secure; HttpOnly; SameSite=Lax',
      );
      assert.deepEqual(parsed, {
        name: 'session_id',
        hasSecure: true,
        hasHttpOnly: true,
        sameSite: 'lax',
      });
    });

    it('trata cookie sem atributos', () => {
      const parsed = parseSetCookieHeader('simple=val');
      assert.deepEqual(parsed, {
        name: 'simple',
        hasSecure: false,
        hasHttpOnly: false,
        sameSite: null,
      });
    });
  });

  describe('inspectSetCookie', () => {
    it('emite error quando cookie de sessão sobre HTTPS não tem Secure', () => {
      const issues = inspectSetCookie('session_id=abc; HttpOnly', true);
      assert.equal(issues.length, 1);
      assert.equal(issues[0].kind, 'insecure_cookie');
      assert.equal(issues[0].severity, 'error');
      assert.match(issues[0].detail, /without the Secure attribute over HTTPS/);
    });

    it('emite warning quando cookie de sessão não tem HttpOnly', () => {
      const issues = inspectSetCookie('session_id=abc; Secure', true);
      assert.equal(issues.length, 1);
      assert.equal(issues[0].kind, 'insecure_cookie');
      assert.equal(issues[0].severity, 'warning');
      assert.match(issues[0].detail, /without the HttpOnly attribute/);
    });

    it('Supabase SSR sb-*-auth-token dispensa HttpOnly por desenho, mas exige Secure sobre HTTPS', () => {
      // Com Secure sem HttpOnly -> limpo (isenção Supabase SSR)
      const cleanSsr = inspectSetCookie('sb-myproj-auth-token=jwt; Secure', true);
      assert.equal(cleanSsr.length, 0);

      // Sem Secure sobre HTTPS -> emite error de Secure
      const missingSecure = inspectSetCookie('sb-myproj-auth-token=jwt', true);
      assert.equal(missingSecure.length, 1);
      assert.equal(missingSecure[0].severity, 'error');
      assert.match(missingSecure[0].detail, /without the Secure attribute/);
    });

    it('SameSite ausente NÃO gera alerta (navegadores assumem Lax)', () => {
      const issues = inspectSetCookie('session_id=abc; Secure; HttpOnly', true);
      assert.equal(issues.length, 0);
    });

    it('SameSite=None sem Secure gera warning', () => {
      const issues = inspectSetCookie('session_id=abc; HttpOnly; SameSite=None', false);
      const noneWarn = issues.find((i) => i.detail.includes('SameSite=None without the Secure attribute'));
      assert.ok(noneWarn);
      assert.equal(noneWarn.severity, 'warning');
    });

    it('cookie de sessão 100% configurado não gera nenhuma issue', () => {
      const issues = inspectSetCookie(
        'session_id=abc; Secure; HttpOnly; SameSite=Strict; Path=/',
        true,
      );
      assert.equal(issues.length, 0);
    });

    it('cookies de analytics/UI ou CSRF ignorados silenciosamente', () => {
      assert.equal(inspectSetCookie('XSRF-TOKEN=val', true).length, 0);
      assert.equal(inspectSetCookie('csrf_token=val', true).length, 0);
      assert.equal(inspectSetCookie('_ga=val', true).length, 0);
      assert.equal(inspectSetCookie('theme=dark', true).length, 0);
    });
  });
});
