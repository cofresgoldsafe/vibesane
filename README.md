# vibesane

Preflight sanity check for vibe-coded web apps, typically under 3 seconds. Zero config, zero runtime dependencies, instant copy-paste AI fix prompts.

## What It Checks

- **Server Availability & Ports:** Scans standard dev ports (`3000`, `3001`, `5173`, `5174`, `8080`, `8000`, `4321`), verifying dual-stack loopback connectivity.
- **Route Sanity & HTTP Status:** Inspects `/` and discovered internal sub-routes for 4xx/5xx failures and slow compiling routes.
- **Masked Errors & Overlays:** Detects Next.js and Vite error overlays, hydration crashes, and unhandled runtime errors returned with HTTP 200.
- **Script Syntax Check:** Compiles application JavaScript files and ES modules (compile only, never executed) to catch unclosed brackets, duplicate identifiers, or missing files that return HTML instead of JS.
- **Secret Leaks & Supabase Keys:** Scans responses and application scripts for high-entropy tokens, Stripe keys, database URIs with passwords, Supabase `service_role` keys (masked as `eyJ****` + last 2 chars; ignoring `anon`), Supabase secret keys (`sb_secret_*`; ignoring `sb_publishable_*`), and private environment variables.
- **Exposed Files (`/.env` & `/.git/config`):** Detects if dev servers or static servers expose sensitive root files (kind `exposed_file`). For `/.env`, lists up to 5 variable names while **strictly guaranteeing that secret values never appear** in details, snippets, code frames, or AI prompts. For `/.git/config`, flags exposed git history without leaking remote URLs.

## Quickstart

Start your local dev server (`npm run dev`), then run in another terminal:

```bash
npx vibesane
```

Check a specific port:

```bash
npx vibesane --port 8080
```

**Requirement:** Node.js `>= 22.13.0`.

## Pipe Directly to Clipboard (`pbcopy` / `clip`)

All scan output goes to `stdout` (`stderr` receives only CLI usage errors, exit code `2`, and unexpected internal errors), so you can pipe the report and AI fix prompt directly to your clipboard:

macOS:

```bash
npx vibesane | pbcopy
```

Windows (`cmd.exe` or PowerShell):

```powershell
npx vibesane | clip
```

> **Windows UTF-8 Note:** `vibesane` emits pure ASCII headers, separators, and code frames so `| clip` works cleanly even under the default Windows codepage (`CP850`). If your own application code contains accented characters (e.g., Portuguese or Spanish) that you want to preserve when copying on Windows:
> - **PowerShell:** `[Console]::OutputEncoding = [Text.Encoding]::UTF8; npx vibesane | Set-Clipboard`
> - **`cmd.exe`:** `chcp 65001 >nul && npx vibesane | clip`

## Real Output Examples

### Clean Scan (All Good)

```text
vibesane: connected to http://localhost:5173 (29ms)
info: checked 1 page, 2 scripts
```

### Sanity Failure (Structured Code Frame & Secret Redaction)

```text
vibesane: sanity check failed on http://localhost:5173 (2 error(s))
error [http_error]: HTTP 500 on script /src/components/Pay.tsx:2:98 - [PARSE_ERROR] Expected `,` or `}` but found `Identifier`
     +-[ src/components/Pay.tsx:2:98 ]
     |
   2 |   const broken = { stripeKey: "sk_live_****abcd", msg: "Olá, senha inválida" b: 2 };
     |                  +                                                                               +
     |                  +---------------------------------------------------------------------------------- Opened here
     |                                                                                                  |
     |                                                                                                  +-- `,` or `}` expected
  ---+
error [secret_leak]: Secret leak on /src/components/Pay.tsx: Stripe secret key (sk_live_****abcd)
info: checked 1 page, 3 scripts

AI FIX PROMPT (copy & paste into Cursor / Claude Code / Gemini CLI):
Target: http://localhost:5173
1. [http_error] HTTP 500 on script /src/components/Pay.tsx:2:98 - [PARSE_ERROR] Expected `,` or `}` but found `Identifier`
      +-[ src/components/Pay.tsx:2:98 ]
      |
    2 |   const broken = { stripeKey: "sk_live_****abcd", msg: "Olá, senha inválida" b: 2 };
      |                  +                                                                               +
      |                  +---------------------------------------------------------------------------------- Opened here
      |                                                                                                  |
      |                                                                                                  +-- `,` or `}` expected
   ---+
2. [secret_leak] Secret leak on /src/components/Pay.tsx: Stripe secret key (sk_live_****abcd)
Instruction (secrets): Move this key to a server-only environment variable (never NEXT_PUBLIC_ / VITE_) and rotate it if it was ever committed or deployed.
Instruction (code): Fix only the error pointed out above; do not refactor unrelated code.
```

## What It Checks

- **Dual-Stack Port Auto-Detection:** Probes `127.0.0.1` and `::1` across `3000, 3001, 5173, 5174, 8080, 8000, 4321` and confirms an active HTTP server.
- **HTTP Status & Route Crawling:** Checks `/` plus up to 10 internal routes (`<a href>`) and up to 5 application scripts/modules (`<script src>` and first-level `/src/` ESM imports) for `4xx`/`5xx` responses.
- **Masked Error Overlays on `200 OK`:** Detects Next.js and Vite runtime/compile error overlays hidden inside `200 OK` HTML responses, including Next 16 RSC/Flight error payloads and Vite/Oxc code frames.
- **Client-Side Secret Leaks:** Scans HTML and JS bundles for exposed secrets (`sk_live_*`, `sk_test_*`, `rk_live_*`, `rk_test_*`, `AIzaSy*`, `ghp_*`, `sk-proj-*`, `sk-ant-*`, `sb_secret_*`, Supabase `service_role` JWTs, `*_SECRET`, `*_PRIVATE_KEY`, `DATABASE_URL` with credentials, and hardcoded `password`/`senha` assignments), resolving the original source file inside Turbopack and Webpack chunks while ignoring public keys (`pk_live_*`, `pk_test_*`, `sb_publishable_*`, `NEXT_PUBLIC_*`, `VITE_*` (except Supabase service_role JWTs, which are flagged even in NEXT_PUBLIC_* / VITE_*), and Supabase `anon` / `authenticated` keys).
- **Exposed Files Detection:** Parallel non-blocking probe for `/.env` and `/.git/config` when the project root is mistakenly exposed. Fails safe and silent on 403, 404, or SPA fallback.
- **Slow Routes:** Flags routes taking `> 1500ms` to return headers as `warning [slow_route]`.
- **Truncated Responses:** Flags responses cut off by size or read timeout as non-fatal `warning [truncated_body]` (reporting the exact cause: exceeded limit, read timeout, or stream error), ensuring large bundles are accounted for.

## Next.js Cold Start (On-Demand Compilation)

Right after starting `next dev`, Next.js compiles routes on demand on the very first request:

- If the root route `/` takes **more than 2 seconds** to compile, the port detector exits with an HTTP timeout (exit code `1`: `port 3000 accepted the connection but took >2s to respond (still compiling?)`).
- If the root route `/` redirects to a local page (e.g., `/` -> `307` to `/login`) that takes longer than the route timeout to compile, `vibesane` outputs:
  ```text
  vibesane: connected to http://localhost:3000 (15ms)
  warning [slow_route]: slow route / -> /login (did not respond within 2000ms - may be dev server compilation; re-run to confirm)
  info: nothing was checked (/ did not respond in time); re-run after the dev server finishes compiling
  ```
  The exit code remains `0` because dev server compilation is not an application defect.
- If sub-routes take too long to compile on first hit, they are reported as `warning [slow_route]` or `info: N route(s) not checked (time budget reached)`.
- **Fix:** Simply **run `npx vibesane` again** — once the dev server has compiled and cached the route, the scan finishes in milliseconds.

## Limitations (What It Does Not Do)

- **No Headless Browser (Not Playwright/Cypress):** Runs fast HTTP/HTML/JS inspection via `fetch`. It does not execute client-side JavaScript, click buttons, submit forms, or detect crashes that only trigger after DOM user interaction.
- **Compile-Time vs Runtime Errors:** Performs syntax check (compile only, never executed). Runtime-only errors (e.g. reassigning a const inside a click handler) are not detected.
- **Server Environment References in Client Strings:** Detects `.env.VAR_NAME` statically via regex in client bundles. Literal strings or user-facing error messages containing such patterns (e.g. `"check your process.env.DATABASE_URL"`) in client components will also trigger `server_env_in_client`.
- **HTML-Based Route Discovery:** Discovers sub-routes from `<a href="...">` links rendered in the HTML of `/`. In pure client-side SPAs where `<div id="root"></div>` is empty and routes exist only inside a client-side router, `vibesane` inspects `/` and up to 5 application JS modules (`/src/*`), but does not navigate client-only routes absent from initial HTML.
- **No Authentication / Session State:** Protected routes redirecting to external login providers are skipped; same-origin redirects are followed up to 3 hops.
- **Deterministic Caps:** Enforces a `2.5s` global crawl budget, up to `10` routes, `5` scripts, `1 MB` per HTML page, and `8 MB` per script.

## CLI Options & Exit Codes

### Options

| Flag | Description |
| :--- | :--- |
| `-p, --port <number>` | Check a specific TCP port (`1-65535`) instead of auto-detecting |
| `-h, --help` | Show CLI usage information |
| `-v, --version` | Print the package version |

### Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | All sanity checks passed (including non-fatal warnings) |
| `1` | Sanity check failed (`http_error`, `masked_error`, `secret_leak`, `server_env_in_client`, `syntax_error`, `exposed_file`) or no local HTTP server found |
| `2` | CLI usage error (invalid flag or invalid `--port` value) |

## License

MIT
