# Changelog

All notable changes to this Cloudflare Workers port are documented here. The
format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

This fork does not follow the upstream version scheme. Entries are grouped by the
order in which work landed on `main`. See the git log for the authoritative record.

## Unreleased

### Removed
- Dead upstream Node.js/Express backend: `app/backend/`, `source/backend/`,
  and `source/backend/tsconfig.json`. The Worker entry point is `src/index.ts`;
  these directories were compiled output and source from the pre-port codebase
  and were never on the runtime path.
- Twig templates under `app/frontend/views/`. HTML is rendered from TypeScript
  string templates in `src/templates/`; no template engine is used.
- `benchmark/` (upstream Jupyter notebooks), unrelated to the Workers port.

### Changed
- `.env.example` now documents the Cloudflare Workers environment model
  (Wrangler secrets, `wrangler.jsonc` vars, `.dev.vars`) instead of the old
  Node.js `HTTP_SERVER_*` variables, which no longer exist.
- `README.md` rewritten: adds a fork-history/credits section, an upstream-vs-fork
  comparison table, license attribution, and an accurate project-structure map.
- Stale comment headers in `src/routes/*.ts` and `src/templates/*.ts` no longer
  reference deleted upstream files.

## Port to Cloudflare Workers

The initial rewrite of [Godotcam/goCamOpenSource](https://github.com/Godotcam/goCamOpenSource)
(Node.js + Express + Twig) to Cloudflare Workers.

### Architecture
- **Runtime:** Cloudflare Workers (edge). Entry point `src/index.ts`.
- **State:** `VerificationSession` Durable Object backed by SQLite, holding
  session state and driving callback dispatch with alarm-based retries.
- **Templates:** HTML rendered as TypeScript strings in `src/templates/` —
  Twig and its template engine were removed entirely.
- **Config:** Wrangler secrets + `wrangler.jsonc` vars; `.dev.vars` for local dev.
  Boot-time check fails closed if `ENCRYPTION_KEY` is missing or not 32 bytes.
- **Static assets:** `app/frontend/` bound via the Workers assets binding
  (`run_worker_first: true`); the router falls through to `env.ASSETS.fetch()`.
- **Analytics:** Analytics Engine binding (`ANALYTICS` / `gocam_events`).

### Security hardening (vs. upstream)
Driven by the adversarial audits in [`review/`](./review/) across six rounds.

- **Crypto:** switched AES-CBC → **AES-GCM** (authenticated encryption);
  separate AES and HMAC keys derived via **HKDF**; payload hash upgraded to
  **SHA-256**; constant-time comparisons everywhere.
- **Key management:** `ENCRYPTION_KEY` gitignored and replaced with a
  placeholder; boot check rejects missing/mis-sized keys. (Note: an old key
  remains in git history — rotate on first deploy.)
- **SSRF defenses:** `isSafeCallbackUrl` validates scheme and blocks private /
  link-local / unspecified addresses (IPv4 and IPv6, including `[::]`);
  `dispatchCallback` uses `redirect: 'manual'` to defeat redirect-following bypass.
- **Cookies / sessions:** `isAgeVerified` cookie hardened (HttpOnly, SameSite,
  bounded TTL); signed session cookie required for `/result/isSuccess`; state
  confirmation guard on `/result/success` and `/result/fail`.
- **XSS / injection:** CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`
  headers; hex colors validated at input and sanitized at render; `linkBack`
  and render-path CSS injection closed; `postMessage` hardening.
- **PII:** logs emit only `stateInt` / `sessionId`; Durable Object returns
  generic errors. Fail-closed on oversize durations; alarm retry cap; DO key
  validation and key-cache poison fix; config-rotation safe.

### Tests
- ~320 unit and integration tests via Vitest, including the
  `@cloudflare/vitest-pool-workers` pool for real Durable Object and
  fetch-handler integration tests. Covers routes, templates (XSS), session
  middleware, encryption, SSRF vectors, and the full DO callback/alarm lifecycle.

### Sync with upstream
- Merged upstream `main` once to pick up Snyk dependency fixes (`d45f4f4`).
  No upstream backend code is on the runtime path.
