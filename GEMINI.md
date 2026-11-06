# GEMINI.md — Memória Consolidada do Projeto (`vibesane`)

## Status do Plano Ativo (2026-11-06)
- **Branch:** `feat/task-2-port-detector`
- **Última tarefa concluída:** Task 2 (Detector de Portas e Servidores Locais, 45/45 testes verdes)
- **Próxima tarefa:** Task 3 (Motor de Testes de Sanidade)

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

---

## Registro de Tarefas Concluídas
- `2026-11-05` — **Task 1 (Setup do Repositório & Tooling):** Concluída e verificada ao vivo (`npm test` com 35/35 testes passando em `node:test`, `npm run typecheck` limpo, `npm pack --dry-run --json` < 500 KB, zero bytes CRLF em `bin/vibesane.js`).
- `2026-11-06` — **Task 2 (Detector de Portas e Servidores Locais):** Concluída e verificada ao vivo (`45/45` testes passando em `node:test` cobrindo IPv4, IPv6, desempate determinístico, `alsoActivePorts`, `non_http`, `http_timeout`, `no_server` e validações de fronteira; `npm run typecheck` limpo).
