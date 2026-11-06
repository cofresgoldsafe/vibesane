# SPEC.md — Vibesane: Kit de Testes Invisíveis de Sanidade para Vibe Coders

> **One-Liner:** Test your vibe-coded web app in 3 seconds. Zero configs, zero setup, zero excuses. Detect silent crashes and get instant copy-paste AI fix prompts.

---

## 1. Visão Geral do Produto & O Problema

### O Cenário Atual
O movimento de *Vibe Coding* permite a desenvolvedores e solopreneurs gerarem telas, rotas e sistemas inteiros em minutos usando agentes de IA (Cursor, Claude Code, Gemini CLI, Copilot). Porém, surge uma dor aguda:
1. **Quebras Silenciosas:** Uma alteração solicitada à IA em uma tela quebra silenciosamente outras rotas (ex: erro 500 em APIs, variáveis de ambiente nulas, loops de renderização).
2. **Aversão a Testes Tradicionais:** Ferramentas como Cypress, Playwright e Jest exigem arquivos de configuração complexos, instalação de navegadores pesados e escrita manual de dezenas de linhas de teste — o oposto da agilidade do vibe coding.
3. **Erros Criptográficos:** Quando algo quebra, o terminal tradicional cospe stack traces ilegíveis que o usuário tem dificuldade de interpretar ou alimentar de volta para a IA.

### A Solução: `vibesane`
Uma CLI ultraleve e determinística que o desenvolvedor roda com um único comando:
```bash
npx vibesane
```
Sem arquivos de configuração. Ela detecta automaticamente o servidor local em execução, faz varredura de sanidade em menos de 3 segundos e, se houver falha, entrega uma mensagem formatada e mastigada pronta para colar no chat da IA para autocorreção.

---

## 2. Especificação Funcional & Critérios de Aceitação (BDD)

### Caso 1: Detecção Automática de Ambiente Local
- **Dado** que o desenvolvedor possui um servidor web rodando localmente (Next.js, Vite, Remix, Fastify, Express, etc.),
- **Quando** ele executa `npx vibesane`,
- **Então** a ferramenta deve inspecionar as portas locais mais comuns (3000, 3001, 5173, 5174, 8080, 8000, 4321), identificar a porta ativa e confirmar a conexão em menos de 500ms, sem exigir parâmetro de URL.

### Caso 2: Varredura de Sanidade Rápida (Preflight Checks)
- **Dado** que o servidor local está respondendo,
- **Quando** a rotina de checagem inicia,
- **Então** ela deve verificar automaticamente:
  1. **Status HTTP e Rotas Vitais:** A rota raiz `/` e páginas mapeadas respondem `200 OK` (sem `500 Internal Server Error`).
  2. **Vazamento de Segredos em HTML/Payloads:** Nenhuma chave com padrões conhecidos (`*_SECRET`, `sk_live_*`, `AIzaSy*`, senhas puras) está exposta no HTML público entregue pelo servidor.
  3. **Tempo de Resposta Crítico:** Alerta se uma rota síncrona demorar mais de 1.5s para responder localmente (indicativo de gargalo ou loop).

### Caso 3: Relatório Amigável & Prompt de Correção para IA (O Diferencial)
- **Dado** que uma falha de sanidade foi identificada,
- **Quando** a execução for finalizada,
- **Então** a CLI deve exibir no terminal:
  - O resumo visual do erro destacado em vermelho/amarelo.
  - Uma seção destacada: **`🤖 AI FIX PROMPT (copy & paste into Cursor / Claude Code / Gemini CLI):`**
  - O texto formatado com contexto do erro, arquivo suspeito e a instrução clara para a IA corrigir sem degradar o restante do código.

---

## 3. Arquitetura Técnica & Linhas Vermelhas

### Pilares Arquiteturais
1. **Zero-Config Real:** Nenhuma obrigatoriedade de arquivo `vibesane.config.json` inicial. Tudo funciona por convenção e inspeção de ambiente.
2. **Ultraleve e Instantâneo:** Não baixa browsers pesados (Chromium/Puppeteer). Utiliza requisições HTTP rápidas nativas (`fetch` do Node.js) e parsing leve de DOM/Headers. O tempo total de execução deve ser inferior a 3 segundos.
3. **Zero Telemetria Oculta:** Total transparência e respeito à privacidade do desenvolvedor.
4. **Multiplataforma:** Suporte nativo e testado em Windows (PowerShell/CMD), macOS e Linux.

### Tecnologias Recomendadas
- **Linguagem:** TypeScript (compilado para ESM puro via `tsc` / `NodeNext`).
- **Runtime:** Node.js >= 22.13.0 (utilizando `fetch`, `node:util` `parseArgs` e `node:util` `styleText` nativos).
- **Bibliotecas de Terminal:** Zero dependências de runtime (`node:util` `parseArgs` e `styleText` nativos substituem `commander` e `picocolors`).
- **Tamanho do Pacote:** Alvo de < 500 KB para download instantâneo via `npx`.

---

## 4. Estrutura Proposta de Diretórios do Projeto

```text
vibesane/
├── bin/
│   └── vibesane.js             # Ponto de entrada executável do npx
├── src/
│   ├── cli.ts                  # Parsing de argumentos e orquestrador
│   ├── scanner/
│   │   ├── port-detector.ts    # Auto-descoberta de servidores locais (3000, 5173, etc.)
│   │   ├── route-crawler.ts    # Descoberta rápida de rotas no framework
│   │   └── security-scan.ts    # Varredura de vazamento de credenciais e secrets
│   ├── reporter/
│   │   ├── terminal-ui.ts      # Renderização visual limpa no terminal
│   │   └── ai-prompt-gen.ts    # Gerador de prompt formatado para colar na IA
│   └── index.ts
├── package.json
├── tsconfig.json
├── README.md                   # Vitrine do repositório (GIF, Quickstart, Badges)
└── LICENSE                     # Licença MIT
```

---

## 5. Roteiro de Tarefas Atômicas (Backlog de Implementação)

- [x] **Task 1: Setup do Repositório & Tooling**
  - [x] Inicializar `package.json` com campos executáveis `bin`.
  - [x] Configurar TypeScript com build leve via `tsc` (ESM `NodeNext`).
  - [x] Definir scripts de build, suíte de testes `node:test` e CI multiplataforma.

- [x] **Task 2: Detector de Portas e Servidores Locais**
  - [x] Implementar varredura assíncrona rápida de portas padrão (3000, 3001, 5173, 5174, 8080, 8000, 4321).
  - [x] Adicionar fallback para porta customizada via flag (`--port 8000`).

- [x] **Task 3: Motor de Testes de Sanidade**
  - [x] Implementar checagem de status HTTP e headers.
  - [x] Implementar analisador de HTML básico para checagem de erros 500 mascarados e credenciais expostas.

- [x] **Task 4: Gerador de Prompt para IA (AI Fix Formatter)**
  - [x] Criar template de prompt determinístico contendo a rota, código HTTP retornado e instrução de correção para Cursor/Claude/Gemini.

- [ ] **Task 5: README de Classe Mundial & Publicação**
  - Criar README com gravação de terminal em GIF.
  - Publicar primeira versão no npm (`v0.1.0`).
  - Preparar roteiro de lançamento no Hacker News e comunidades de Vibe Coding.
