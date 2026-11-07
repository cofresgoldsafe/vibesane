import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { checkScriptSyntax, formatSyntaxCodeFrame } from '../dist/scanner/syntax-check.js';
import { runVibesane } from '../dist/index.js';

function startHttpServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      resolve({
        port,
        close: () => new Promise((cb) => srv.close(cb)),
      });
    });
  });
}

describe('Syntax Checker (BDD) — v0.1.5', () => {
  describe('1. Script Clássico (node:vm)', () => {
    it('1a. Identifica }); sobrando com Unexpected token e codeFrame com ^', async () => {
      const code = 'function init() {\n  console.log("hello");\n});';
      const issue = await checkScriptSyntax({
        code,
        route: '/public/app.js',
      });

      assert.ok(issue, 'Deve gerar issue para syntax error clássico');
      assert.equal(issue.kind, 'syntax_error');
      assert.equal(issue.severity, 'error');
      assert.equal(issue.route, '/public/app.js');
      assert.ok(issue.detail.includes('Syntax error on script /public/app.js'));
      assert.ok(issue.detail.includes('Unexpected token') || issue.detail.includes("Unexpected token ')'"));
      assert.ok(issue.codeFrame, 'Deve incluir codeFrame');
      assert.ok(issue.codeFrame.includes('^'), 'Frame deve ter ponteiro ^');
      assert.ok(issue.codeFrame.includes('});'), 'Frame deve exibir linha do erro');
    });

    it('1b. Identifica const duplicada no topo e dentro de função', async () => {
      const codeTop = 'const maxItems = 10;\nconst maxItems = 20;';
      const issueTop = await checkScriptSyntax({
        code: codeTop,
        route: '/app.js',
      });
      assert.ok(issueTop);
      assert.ok(issueTop.detail.includes('has already been declared'));

      const codeFunc = 'function run() {\n  const flag = true;\n  const flag = false;\n}';
      const issueFunc = await checkScriptSyntax({
        code: codeFunc,
        route: '/func.js',
      });
      assert.ok(issueFunc);
      assert.ok(issueFunc.detail.includes('has already been declared'));
    });

    it('1c. Identifica Unexpected end of input (listener ou bloco não fechado)', async () => {
      const code = 'document.addEventListener("DOMContentLoaded", () => {\n  console.log("ready");\n';
      const issue = await checkScriptSyntax({
        code,
        route: '/listener.js',
      });
      assert.ok(issue);
      assert.ok(
        issue.detail.includes('Unexpected end of input') ||
          issue.detail.includes('missing ) after argument list'),
        `Mensagem esperava end of input, obteve: ${issue.detail}`,
      );
    });
  });

  describe('2. Erros exclusivos de runtime (limitação documentada)', () => {
    it('2a. const s=1; function g(){ s=2; } passa sem nenhuma issue (erro em tempo de execução)', async () => {
      const code = 'const s = 1;\nfunction g() {\n  s = 2;\n}\n';
      const issue = await checkScriptSyntax({
        code,
        route: '/runtime-only.js',
      });
      assert.equal(issue, null, 'Não deve emitir issue para erro em runtime');
    });
  });

  describe('3. Módulos ES (node --check)', () => {
    it('3a. ESM válido com import, export e import.meta não gera nenhuma issue', async () => {
      const code = [
        'import { useState } from "react";',
        'export const API_URL = import.meta.env?.VITE_API || "/api";',
        'export default function App() { return useState(0); }',
      ].join('\n');

      const issue = await checkScriptSyntax({
        code,
        route: '/src/App.js',
      });
      assert.equal(issue, null, 'ESM válido não deve emitir issue');
    });

    it('3b. ESM com erro de sintaxe gera syntax_error com linha, coluna e frame', async () => {
      const code = [
        'import { from "./utils.js";',
        'export const value = 42;',
      ].join('\n');

      const issue = await checkScriptSyntax({
        code,
        route: '/src/broken-esm.js',
      });
      assert.ok(issue);
      assert.equal(issue.kind, 'syntax_error');
      assert.equal(issue.severity, 'error');
      assert.ok(issue.detail.includes('Syntax error on script /src/broken-esm.js'));
      assert.ok(issue.codeFrame);
      assert.ok(issue.codeFrame.includes('^'));
      assert.ok(issue.codeFrame.includes('import { from'));
    });
  });

  describe('4. HTML retornado no lugar de JavaScript (SPA Fallback)', () => {
    it('4a. Script com corpo iniciando com < emite detalhe descritivo trazendo a rota do script', async () => {
      const htmlBody = '<!DOCTYPE html><html><head><title>App</title></head><body>Root</body></html>';
      const issue = await checkScriptSyntax({
        code: htmlBody,
        route: '/missing.js',
      });

      assert.ok(issue);
      assert.equal(issue.kind, 'syntax_error');
      assert.equal(
        issue.detail,
        'Script /missing.js returned HTML instead of JavaScript (the file probably does not exist and the server fell back to index.html)',
      );
    });

    it('4b. Script com Content-Type text/html também é detectado', async () => {
      const issue = await checkScriptSyntax({
        code: '   \n  \t  <html><body>Fallback</body></html>',
        route: '/not-found.js',
        contentType: 'text/html; charset=utf-8',
      });

      assert.ok(issue);
      assert.equal(issue.kind, 'syntax_error');
      assert.ok(issue.detail.includes('Script /not-found.js returned HTML instead of JavaScript'));
    });

    it('4c. Content-Type com json é pulado sem emitir syntax_error', async () => {
      const jsonBody = '{"name": "app", "version": 1}';
      const issue = await checkScriptSyntax({
        code: jsonBody,
        route: '/data.json',
        contentType: 'application/json',
      });
      assert.equal(issue, null, 'JSON não deve ser tratado como script JS com erro');
    });
  });

  describe('5. Bypass de Módulos Transformados pelo Vite (/@vite/client)', () => {
    it('5a. Módulo que contém /@vite/client é pulado imediatamente (custo zero de subprocesso)', async () => {
      const viteCode = 'import "/@vite/client";\nimport.meta.hot.accept();\nconsole.log("vite module");';
      const issue = await checkScriptSyntax({
        code: viteCode,
        route: '/src/main.tsx',
      });
      assert.equal(issue, null, 'Deve retornar null imediatamente');
    });

    it('5b. Módulo quando rootHasViteClient é true pula abertura de subprocesso', async () => {
      const esmCode = 'import React from "react";\nconsole.log("clean");';
      const issue = await checkScriptSyntax({
        code: esmCode,
        route: '/src/main.tsx',
        isModule: true,
        rootHasViteClient: true,
      });
      assert.equal(issue, null, 'Deve retornar null sem abrir subprocesso');
    });
  });

  describe('6. Performance, Arquivo Grande (~4 MB) e Linha Longa Minificada', () => {
    it('6a. Arquivo grande válido (~4.2 MB) é compilado sem erro e mede tempo real', async () => {
      const parts = ['const x = 1;\n'];
      for (let i = 0; i < 130000; i++) {
        parts.push(`function fn_${i}() { return ${i}; }\n`);
      }
      const hugeCode = parts.join('');
      assert.ok(hugeCode.length > 4 * 1024 * 1024, 'Arquivo deve ter > 4 MB');

      const t0 = performance.now();
      const issue = await checkScriptSyntax({
        code: hugeCode,
        route: '/bundle.js',
      });
      const elapsed = performance.now() - t0;

      assert.equal(issue, null, 'Arquivo válido não gera erro');
      assert.ok(elapsed > 0, 'Tempo decorrido medido');
    });

    it('6b. Linha minificada longa (> 160 cols) tem o codeFrame recortado em ~160 caracteres', () => {
      const longPrefix = 'const a=1;'.repeat(30); // 300 caracteres
      const longSuffix = 'const b=2;'.repeat(30);
      const targetLine = `${longPrefix} const broken = {; ${longSuffix}`;
      const code = `// header\n${targetLine}\n// footer`;
      const errCol = longPrefix.length + 18;

      const frame = formatSyntaxCodeFrame(code, 2, errCol);
      assert.ok(frame.includes('...'), 'Deve conter elipses para linha longa');
      assert.ok(frame.includes('^'), 'Deve alinhar ponteiro');
      const lines = frame.split('\n');
      const codeLine = lines.find((l) => l.includes('...'));
      assert.ok(codeLine, 'Linha exibida deve ter sido cortada');
      assert.ok(codeLine.length <= 185, `Linha cortada não deve exceder tamanho seguro (${codeLine.length})`);
    });

    it('6c. Unexpected end of input em linha única minificada aponta para o fim do código', async () => {
      const minified = 'const a=1; const b=2; document.addEventListener("click", () => {';
      const issue = await checkScriptSyntax({
        code: minified,
        route: '/bundle.min.js',
      });
      assert.ok(issue);
      assert.ok(issue.codeFrame);
      assert.ok(issue.codeFrame.includes('^'));
      const frameLines = issue.codeFrame.split('\n');
      const codeLine = frameLines.find((l) => l.includes('addEventListener'));
      const pointerLine = frameLines.find((l) => l.includes('^'));
      assert.ok(codeLine, 'Deve exibir a linha do código');
      assert.ok(pointerLine, 'Deve exibir o ponteiro');
      assert.ok(
        pointerLine.indexOf('^') >= codeLine.length - 2,
        `Ponteiro deve apontar para o final do código (col ${pointerLine.indexOf('^')} vs linha ${codeLine.length})`,
      );
    });
  });

  describe('7. Mascaramento Estrito de Segredos e Caminhos no codeFrame', () => {
    it('7a. Chave secreta falsa e caminhos absolutos de SO são higienizados na linha do erro', () => {
      const fakeStripe = ['sk', 'live', '99998888777766665555444433332222'].join('_');
      const code = `const key = "${fakeStripe}";\nconst path = "C:\\\\Users\\\\Administrator\\\\secret.js";\n});`;

      const frame = formatSyntaxCodeFrame(code, 3, 2);
      assert.ok(frame.includes('sk_live_****2222'), 'Chave deve ser mascarada');
      assert.equal(frame.includes('999988887777'), false, 'Não deve expor miolo da chave');
      assert.equal(frame.includes('C:\\Users\\Administrator'), false, 'Não deve expor caminho absoluto');
    });
  });

  describe('8. Teste de Integração Ponta a Ponta com Servidor Local', () => {
    it('8a. Servidor servindo index.html + app.js com }); sobrando retorna exit code 1 e syntax_error', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<!DOCTYPE html><html><head><script src="/app.js"></script></head><body>Login</body></html>');
          return;
        }
        if (url === '/app.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end('function login() {\n  console.log("booting");\n});');
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const result = await runVibesane({ port: srv.port });
        assert.equal(result.ok, false, 'Deve falhar a sanidade');
        const syntaxIssue = result.issues.find((i) => i.kind === 'syntax_error');
        assert.ok(syntaxIssue, 'Deve reportar kind syntax_error');
        assert.equal(syntaxIssue.route, '/app.js');
        assert.ok(result.message.includes('error [syntax_error]:'));
        assert.ok(result.aiPrompt, 'Deve gerar AI FIX PROMPT');
        assert.ok(result.aiPrompt.includes('[syntax_error]'));
        assert.ok(result.aiPrompt.includes('/app.js'));
        assert.ok(result.aiPrompt.includes('Fix only the error pointed out above'));
      } finally {
        await srv.close();
      }
    });

    it('8b. O mesmo servidor com app.js corrigido retorna exit code 0 e ok: true', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<!DOCTYPE html><html><head><script src="/app.js"></script></head><body>Login</body></html>');
          return;
        }
        if (url === '/app.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end('function login() {\n  console.log("booting");\n}\nconsole.log("ready");');
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const result = await runVibesane({ port: srv.port });
        assert.equal(result.ok, true, 'Deve passar limpo');
        assert.equal(result.issues.length, 0);
        assert.ok(result.message.includes('info: checked 1 page, 1 script'));
      } finally {
        await srv.close();
      }
    });

    it('8c. Falsos positivos evitados: <script type="text/babel"> e <script type="application/json"> pulam checagem', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`<!DOCTYPE html><html><head>
            <script type="text/babel" src="/app.jsx"></script>
            <script type="application/json" src="/config.json"></script>
          </head><body>App</body></html>`);
          return;
        }
        if (url === '/app.jsx') {
          // Sintaxe JSX pura que o node:vm não compilaria diretamente
          res.writeHead(200, { 'Content-Type': 'text/babel' });
          res.end('const element = <h1>Hello JSX</h1>;');
          return;
        }
        if (url === '/config.json') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"theme": "dark"}');
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const result = await runVibesane({ port: srv.port });
        assert.equal(result.ok, true, 'Não deve falhar sanidade para text/babel ou application/json');
        const syntaxIssues = result.issues.filter((i) => i.kind === 'syntax_error');
        assert.equal(syntaxIssues.length, 0);
      } finally {
        await srv.close();
      }
    });

    it('8d. Script com type="TEXT/JAVASCRIPT" quebrado continua sendo checado e detecta erro', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<!DOCTYPE html><html><head><script type="TEXT/JAVASCRIPT" src="/legacy.js"></script></head><body>App</body></html>');
          return;
        }
        if (url === '/legacy.js') {
          res.writeHead(200, { 'Content-Type': 'text/javascript' });
          res.end('function run() { console.log(1); });');
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const result = await runVibesane({ port: srv.port });
        assert.equal(result.ok, false);
        const syntaxIssue = result.issues.find((i) => i.kind === 'syntax_error' && i.route === '/legacy.js');
        assert.ok(syntaxIssue, 'Deve detectar erro em script com type=TEXT/JAVASCRIPT');
      } finally {
        await srv.close();
      }
    });

    it('8e. Script com type="module" quebrado continua sendo checado e detecta erro', async () => {
      const srv = await startHttpServer((req, res) => {
        const url = req.url ?? '/';
        if (url === '/') {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<!DOCTYPE html><html><head><script type="module" src="/module.js"></script></head><body>App</body></html>');
          return;
        }
        if (url === '/module.js') {
          res.writeHead(200, { 'Content-Type': 'application/javascript' });
          res.end('import { from "./utils.js";');
          return;
        }
        res.writeHead(404);
        res.end();
      });

      try {
        const result = await runVibesane({ port: srv.port });
        assert.equal(result.ok, false);
        const syntaxIssue = result.issues.find((i) => i.kind === 'syntax_error' && i.route === '/module.js');
        assert.ok(syntaxIssue, 'Deve detectar erro em script com type=module');
      } finally {
        await srv.close();
      }
    });
  });
});
