import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  extractSourceMapComment,
  deriveSourceMapUrl,
  resolveSourceMapTarget,
  isLegitimateSourceMap,
  createExposedSourceMapIssue,
} from '../dist/rules/source-maps.js';

describe('rules: source maps (exposed_source_map)', () => {
  describe('extractSourceMapComment', () => {
    it('extrai comentário sourceMappingURL com //#', () => {
      const code = 'function hello() { return 1; }\n//# sourceMappingURL=app.js.map';
      assert.equal(extractSourceMapComment(code), 'app.js.map');
    });

    it('extrai comentário sourceMappingURL com //@', () => {
      const code = 'console.log("x");\n//@ sourceMappingURL=/static/main.js.map';
      assert.equal(extractSourceMapComment(code), '/static/main.js.map');
    });

    it('retorna null se não houver anotação de sourcemap', () => {
      assert.equal(extractSourceMapComment('const a = 1;'), null);
      assert.equal(extractSourceMapComment(''), null);
    });
  });

  describe('deriveSourceMapUrl', () => {
    it('adiciona .map removendo querystrings', () => {
      assert.equal(deriveSourceMapUrl('/assets/index.js'), '/assets/index.js.map');
      assert.equal(deriveSourceMapUrl('/app.js?v=123'), '/app.js.map');
    });
  });

  describe('resolveSourceMapTarget', () => {
    it('ignora sourceMappingURL que começa com data: (inline sourcemap)', () => {
      const inlineComment = 'data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozfQ==';
      assert.equal(resolveSourceMapTarget(inlineComment, '/bundle.js', 'https://example.com'), null);
      assert.equal(resolveSourceMapTarget('DATA:application/json;base64,abc', '/bundle.js', 'https://example.com'), null);
    });

    it('ignora sourceMappingURL que aponta para outra origem (CDN externa)', () => {
      const cdnComment = 'https://cdn.external.net/libs/bundle.js.map';
      assert.equal(resolveSourceMapTarget(cdnComment, '/assets/bundle.js', 'https://example.com'), null);
      assert.equal(resolveSourceMapTarget('//cdn.external.net/libs/bundle.js.map', '/assets/bundle.js', 'https://example.com'), null);
    });

    it('resolve caminhos relativos e absolutos da mesma origem', () => {
      assert.equal(
        resolveSourceMapTarget('bundle.js.map', '/assets/bundle.js', 'https://example.com'),
        '/assets/bundle.js.map',
      );
      assert.equal(
        resolveSourceMapTarget('/static/bundle.js.map', '/assets/bundle.js', 'https://example.com'),
        '/static/bundle.js.map',
      );
      assert.equal(
        resolveSourceMapTarget('https://example.com/assets/bundle.js.map', '/assets/bundle.js', 'https://example.com'),
        '/assets/bundle.js.map',
      );
    });

    it('faz fallback para deriveSourceMapUrl quando não há comentário', () => {
      assert.equal(
        resolveSourceMapTarget(null, '/assets/bundle.js', 'https://example.com'),
        '/assets/bundle.js.map',
      );
    });
  });

  describe('isLegitimateSourceMap', () => {
    it('rejeita corpo que começa com < (fallback de SPA que devolve HTML)', () => {
      const htmlFallback = '<!DOCTYPE html><html><body>SPA Root</body></html>';
      assert.equal(isLegitimateSourceMap(htmlFallback, 'text/html'), false);
      assert.equal(isLegitimateSourceMap('  <html lang="pt">...</html>'), false);
    });

    it('rejeita quando Content-Type contém text/html', () => {
      assert.equal(isLegitimateSourceMap('{"version":3,"sources":["a.js"]}', 'text/html; charset=utf-8'), false);
    });

    it('rejeita JSON malformado ou vazio', () => {
      assert.equal(isLegitimateSourceMap('not a json'), false);
      assert.equal(isLegitimateSourceMap(''), false);
      assert.equal(isLegitimateSourceMap('{}'), false);
    });

    it('rejeita JSON sem version ou com sources vazio', () => {
      assert.equal(isLegitimateSourceMap('{"version":3,"sources":[]}'), false);
      assert.equal(isLegitimateSourceMap('{"sources":["a.js"]}'), false);
    });

    it('aprova sourcemap real com version e array sources', () => {
      const realMap = JSON.stringify({
        version: 3,
        file: 'bundle.js',
        sources: ['src/index.ts', 'src/util.ts'],
        mappings: 'AAAA,SAAS',
      });
      assert.equal(isLegitimateSourceMap(realMap, 'application/json'), true);
      assert.equal(isLegitimateSourceMap(realMap), true);
    });
  });

  describe('createExposedSourceMapIssue', () => {
    it('gera issue warning com detalhe descritivo', () => {
      const issue = createExposedSourceMapIssue('/assets/index.js.map');
      assert.equal(issue.kind, 'exposed_source_map');
      assert.equal(issue.severity, 'warning');
      assert.equal(issue.route, '/assets/index.js.map');
      assert.match(issue.detail, /Production source map is publicly accessible at \/assets\/index\.js\.map/);
    });
  });
});
