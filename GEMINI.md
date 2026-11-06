# GEMINI.md — Memória Consolidada do Projeto (`vibesane`)

## Status do Plano Ativo (2026-11-05)
- **Branch:** `feat/task-1-setup`
- **Última tarefa concluída:** Task 1 (Setup do Repositório & Tooling, 35/35 testes verdes)
- **Próxima tarefa:** Task 2 (Detector de Portas e Servidores Locais)

---

## Decisões Arquiteturais Travadas
- **Runtime & Módulo:** `engines.node: ">=22.13.0"` e `"type": "module"` (ESM puro compilado via `tsc` / `NodeNext`, zero suporte CJS desnecessário).
- **Zero Dependências de Runtime:** `node:util` `parseArgs` para CLI, `node:util` `styleText` com suporte nativo a `NO_COLOR`/`isTTY` para cores na Task 4, e `fetch` nativo estável.
- **Códigos de Saída Padronizados (`EXIT_CODES`):** `0` (`OK`), `1` (`SANITY_FAILURE`), `2` (`USAGE_ERROR`).
- **Precedência Absoluta de Flags na CLI:** `--help` (`-h`) > `--version` (`-v`) > validação estrita de `--port` (`-p`) via `/^[1-9]\d*$/` e faixa `1..65535` (sem permitir `--port` repetido ou posicionais soltos).
- **Testabilidade em Memória:** `src/cli.ts` exporta `main(argv, io): Promise<number>` sem chamar `process.exit()`; `bin/vibesane.js` apenas atribui `process.exitCode`.
- **Portabilidade Windows/macOS/Linux:** `.gitattributes` com `* text=auto eol=lf`, `package-lock.json` versionado, scripts sem comandos Unix (`fs.rmSync` nativo), `spawnSync` condicional no Windows para evitar `DEP0190` e CI em `{ubuntu-latest, windows-latest, macos-latest} × {'22.13', '24'}`.

---

## Registro de Tarefas Concluídas
- `2026-11-05` — **Task 1 (Setup do Repositório & Tooling):** Concluída e verificada ao vivo (`npm test` com 35/35 testes passando em `node:test`, `npm run typecheck` limpo, `npm pack --dry-run --json` < 500 KB, zero bytes CRLF em `bin/vibesane.js`).
