# GEMINI.md — Memória Consolidada do Projeto (`vibesane`)

## Status do Plano Ativo (2026-11-06)
- **Branch:** `feat/task-3-sanity-engine`
- **Última tarefa concluída:** Task 3 (Motor de Testes de Sanidade + 5 ajustes do Red Team, 62/62 testes verdes)
- **Próxima tarefa:** Task 4 (Gerador de Prompt para IA — AI Fix Formatter)

---

## Decisões Arquiteturais Travadas
- **Runtime & Módulo:** `engines.node: ">=22.13.0"` e `"type": "module"` (ESM puro compilado via `tsc` / `NodeNext`, zero suporte CJS desnecessário).
- **Zero Dependências de Runtime:** `node:util` `parseArgs` para CLI, `node:util` `styleText` com suporte nativo a `NO_COLOR`/`isTTY` para cores na Task 4, e `fetch` nativo estável.
- **Códigos de Saída Padronizados (`EXIT_CODES`):** `0` (`OK`), `1` (`SANITY_FAILURE`), `2` (`USAGE_ERROR`).
- **Precedência Absoluta de Flags na CLI:** `--help` (`-h`) > `--version` (`-v`) > validação estrita de `--port` (`-p`) via `/^[1-9]\d*$/` e faixa `1..65535` (sem permitir `--port` repetido ou posicionais soltos).
- **Testabilidade em Memória:** `src/cli.ts` exporta `main(argv, io): Promise<number>` sem chamar `process.exit()`; `bin/vibesane.js` apenas atribui `process.exitCode`.
- **Portabilidade Windows/macOS/Linux:** `.gitattributes` com `* text=auto eol=lf`, `package-lock.json` versionado, scripts sem comandos Unix (`fs.rmSync` nativo), `spawnSync` condicional no Windows para evitar `DEP0190` e CI em `{ubuntu-latest, windows-latest, macos-latest} × {'22.13', '24'}`.
- **Detector de Portas em 2 Etapas (`src/scanner/port-detector.ts`):** `DEFAULT_PORTS = [3000, 3001, 5173, 5174, 8080, 8000, 4321]` (sem `5000` para evitar falso positivo com AirPlay no macOS). Etapa 1 faz probe TCP dual-stack explícito (`127.0.0.1` e `::1` em paralelo, `DEFAULT_TCP_TIMEOUT_MS = 300`) com vitória determinística por prioridade (portas de maior prioridade nunca são abortadas prematuramente) e coleta de `alsoActivePorts`. Etapa 2 faz confirmação HTTP única (`DEFAULT_HTTP_TIMEOUT_MS = 2000`) direto no IP vencedor (`host: '127.0.0.1' | '::1'`) sem header `Host` manual, distinguindo `no_server`, `non_http` e `http_timeout`.
- **Contrato `VibesaneResult` (0.x):** `port: number | null` (evoluído do `'auto'` do stub da Task 1), expondo `host`, `url` (`http://localhost:<port>`), `statusCode`, `alsoActivePorts`, `checkedPorts` e `reason`.
- **Reuso da Resposta Raiz (`rootResponse`) e Proteção de Streaming (`src/scanner/port-detector.ts`):** `detectServer` decide `ok: true` na chegada dos headers HTTP e lê o body de `/` com orçamento separado (`DEFAULT_BODY_READ_TIMEOUT_MS = 500`, `MAX_BODY_BYTES = 1 MB`), retornando body parcial (`truncated: true`) sem gerar `http_timeout` em SSR streaming e eliminando segundo `GET /` no crawler.
- **Crawler com Orçamento Global e Concorrência Limitada (`src/scanner/route-crawler.ts`):** `DEFAULT_SCAN_BUDGET_MS = 2500`, `DEFAULT_MAX_CONCURRENCY = 4`, `DEFAULT_MAX_ROUTES = 10`, `DEFAULT_MAX_SCRIPTS = 5`, `MAX_REDIRECTS = 3` (apenas mesma origem via `new URL`). Quando o orçamento expira, rotas pendentes vão para `skippedRoutes` (`not checked (time budget reached)`) sem reprovar `ok` nem alterar o exit code.
- **Priorização de `<script src>` e Imports ESM Locais:** Exclui infraestrutura (`/node_modules/`, `/@vite/`, `/@react-refresh`, `webpack`, `main-app`, `polyfills`, `react-refresh`, `framework-`, `turbopack-`, `node_modules_`, `next_dist`, `turbopack`, `%5bturbopack%5d`, `polyfill`, `_buildmanifest`, `_ssgmanifest` em `EXCLUDED_SCRIPT_SUBSTRINGS` / `isExcludedFrameworkScript`, cobrindo Next 16 com Turbopack) e prioriza código da aplicação (`/src/`, `app/page`, `app/layout`, `pages/`), seguindo imports ESM de 1º nível em `/src/` até o teto de 5 scripts. Scripts/módulos com status `4xx`/`5xx` geram `http_error` (`severity: 'error'`) com `sanitizeErrorSnippet` mascarando segredos.
- **Rota Lenta (`slow_route` > 1500ms) e Timeout de Sub-rota:** Medida pelo tempo até os headers (`headersElapsedMs`), isenta no `GET /` inicial e em `<script src>`, emitida como `severity: 'warning'` (mantendo `ok: true` e exit code `0`). Sub-rotas que estouram `routeTimeoutMs` (`TimeoutError`/`AbortError` sem `budgetController.signal.aborted`) também viram `slow_route` (`severity: 'warning'`, mantendo `ok: true` e exit code `0`), reservando `http_error` para falhas reais de conexão ou loops `> 3` redirects.
- **Scanner de Segurança e Erros Mascarados (`src/scanner/security-scan.ts`):** `detectMaskedError` (apenas HTML) busca marcadores exatos (`nextjs__container_errors`, `"Unhandled Runtime Error"`, `__next_error__`, `vite-error-overlay`, `[plugin:vite:`). Páginas com status `>= 400` e marcador de `masked_error` emitem um único `http_error` consolidado sem duplicar `masked_error`. `scanSecrets` ignora `pk_live_`, `pk_test_`, `NEXT_PUBLIC_*`, `VITE_*`, `<input type="password">` e valores de `password`/`senha`/`passwd`/`pwd` com espaços em branco (evitando falsos positivos em textos de validação de UI), aplicando `redactSecret` (`sk_live_****ab12`) no contrato `SanityIssue` (`kind`, `severity`, `route`, `detail`, `maskedSnippet`).

---

## Backlog / Requisitos Capturados para a Task 4 (AI Fix Formatter & Terminal UI)
1. Extrair do payload/JSON de erro do Vite os campos estruturados (`message`, arquivo/`id`, linha/coluna/`loc`) para que o prompt de correção mostre arquivo e linha sem ruído ou truncamento cego em 140 caracteres.
2. Limpar query strings de cache-busting do Vite (`?t=<timestamp>` / `&t=<timestamp>`) ao exibir caminhos de scripts/módulos no relatório e no prompt.
3. Mascaramento específico de senhas mostrando apenas o 1º caractere (`G***`), em vez de prefixo + sufixo (`Gol****26`).

---

## Registro de Tarefas Concluídas
- `2026-11-05` — **Task 1 (Setup do Repositório & Tooling):** Concluída e verificada ao vivo (`npm test` com 35/35 testes passando em `node:test`, `npm run typecheck` limpo, `npm pack --dry-run --json` < 500 KB, zero bytes CRLF em `bin/vibesane.js`).
- `2026-11-06` — **Task 2 (Detector de Portas e Servidores Locais):** Concluída e verificada ao vivo (`45/45` testes passando em `node:test` cobrindo IPv4, IPv6, desempate determinístico, `alsoActivePorts`, `non_http`, `http_timeout`, `no_server` e validações de fronteira; `npm run typecheck` limpo).
- `2026-11-06` — **Task 3 (Motor de Testes de Sanidade):** Concluída e verificada ao vivo com os 5 ajustes do Red Team (`62/62` testes passando em `node:test`, zero alterações nos 45 testes das Tasks 1 e 2, `npm run typecheck` limpo).
