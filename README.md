![image](https://github.com/Godotcam/goCamOpenSource/assets/169826477/881f387a-a09d-417e-a1fb-67dab35c5072)


# Go.cam Age Verification — Cloudflare Workers Edition

[GO.cam](https://go.cam/) offers a simple, easy-to-use application for verifying age online.
With just a few clicks, it allows verifying the age of users who wish to access sites restricted to minors.

Two methods of age verification are available: facial recognition (selfie) and ID document verification (ID card, passport, or driver's license).

For the selfie verification, GO.cam uses the smartphone camera or computer webcam to assess the user's age through artificial intelligence. If the detected age is too close to the legal age, another verification method is suggested.

### GO.cam is certified

We are constantly working closely with regulators from many countries to certify GO.cam.

Authorities that have already certified us:

* [Central Authority for the Supervision and Protection of Minors on the Internet in Germany](https://www.kjm-online.de/pressemitteilungen/altersverifikation-persona-gocam/)
* [Age Check Certification Scheme](https://accscheme.com/registry/age-estimation/gsi-development-sas/)

[ASACP](https://www.asacp.org/) recommends Go.cam as a solution for protecting minors online by guaranteeing secure access to adult content.

---

## About this fork

This is a **community port** of [Godotcam/goCamOpenSource](https://github.com/Godotcam/goCamOpenSource) (upstream), rewritten to run entirely on [Cloudflare Workers](https://developers.cloudflare.com/workers/). It is **not** affiliated with or endorsed by GO.cam.

### What changed from upstream

| Aspect | Upstream | This fork |
| --- | --- | --- |
| Runtime | Node.js + Express | Cloudflare Workers (edge) |
| Storage | In-memory / file-backed | Durable Objects with SQLite |
| Templates | Twig (`*.twig`) | HTML rendered as TypeScript strings (no template engine) |
| Config | `.env` file | Wrangler secrets + `wrangler.jsonc` vars |
| Crypto | Custom AES-CBC + raw keys | AES-GCM with HKDF-derived keys, constant-time compares |
| Tests | None included | ~320 unit + integration tests (Vitest, workers pool) |

The frontend assets (`app/frontend/static/`) and their build pipeline (`source/frontend/`, `script/gulpfile.js`) are preserved from upstream. The original Node.js/Express backend (`source/backend/`, `app/backend/`) and Twig templates were **removed** — they are not used by the Worker.

See [`CHANGELOG.md`](./CHANGELOG.md) for the full change history, and the [`review/`](./review/) directory for the adversarial security/quality audits that drove the crypto and SSRF hardening.

### License

This project inherits the upstream license: **AGPL-3.0**. See [`LICENSE`](./LICENSE). The example integrations under `example/` are MIT-licensed upstream; a standalone version lives at [Godotcam/goCamOpenSourceExamples](https://github.com/Godotcam/goCamOpenSourceExamples).

---

## Prerequisites

- Node.js 18+ and npm
- A Cloudflare account (for deployment)

## Setup

Install dependencies:

```sh
npm install
```

Generate a 32-byte `ENCRYPTION_KEY` (the app enforces exactly 32 bytes UTF-8):

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('latin1'))"
```

Set it as a Wrangler secret (used by both `wrangler dev` and `wrangler deploy`):

```sh
npx wrangler secret put ENCRYPTION_KEY
```

For local development you can instead place it in a `.dev.vars` file at the repo root (this file is gitignored):

```
ENCRYPTION_KEY="<your-32-byte-key>"
```

`.env.example` documents every variable the Worker reads (secrets and non-secrets) and how to set each one. The Worker fails closed at boot if `ENCRYPTION_KEY` is missing or the wrong length.

## Development

Start the local Wrangler dev server:

```sh
npm run dev
```

The Worker serves on `http://localhost:8787` by default. Some features (e.g. webcam access) require HTTPS; for a first local run, `localhost` is treated as a secure context by browsers.

## Deployment

Deploy to Cloudflare Workers:

```sh
npm run deploy
```

## Type checking

Run the TypeScript compiler in check-only mode:

```sh
npm run types
```

## Tests

Run the full Vitest suite (unit + integration):

```sh
npm test
```

Watch mode:

```sh
npm run test:watch
```

Run the suite under the Cloudflare Workers runtime pool (Durable Object + fetch-handler integration tests):

```sh
npm run test:workers
```

The suite covers: route handlers, HTML templates (XSS escaping), session cookie middleware (HMAC signing), encryption helpers, SSRF / URL-validation edge cases, and full Durable Object lifecycle (callback dispatch, alarm retries, state transitions).

## Building frontend assets

The frontend CSS and JS are built from `source/frontend/` into `app/frontend/static/`. These build scripts are only needed when changing frontend assets:

```sh
npm run build:css        # SCSS → CSS via sass
npm run build:frontend   # TS → bundled JS via gulp
```

## Example implementation

By running this project you can walk through both verification flows: a full-page redirect or an iframe overlay.

Standalone example integrations in various programming languages live in the `example` folder. A MIT-licensed alternative for the example code is available at [Godotcam/goCamOpenSourceExamples](https://github.com/Godotcam/goCamOpenSourceExamples).

## Project structure

```
.
├── src/                  # Worker source
│   ├── index.ts          # Entry point: router, fetch handler, Env bindings
│   ├── config.ts         # Typed config (reads env, caches per isolate)
│   ├── routes/           # HTTP route handlers (index, token, result)
│   ├── lib/              # Pure helpers (encryption, url validation, parse, color, response, do)
│   ├── middleware/        # Session cookie signing/verification (HMAC)
│   ├── templates/        # HTML templates rendered as strings (no engine)
│   └── durable-objects/  # VerificationSession DO (SQLite-backed state + callback retries)
├── app/frontend/         # Static assets served by the Worker (img, css, js)
├── source/frontend/      # Frontend source (SCSS + TS) consumed by the build scripts
├── script/gulpfile.js    # Frontend JS build pipeline (gulp)
├── test/                 # Vitest suite (unit, integration, DO, fetch-handler)
├── example/              # Standalone integration examples (Node.js, PHP)
├── review/               # Adversarial security/crypto/logic/quality audits
├── docs/                 # QA reports and remediation plans
├── wrangler.jsonc        # Cloudflare Workers config (bindings, assets, DOs, analytics)
├── vitest.config.ts      # Test configuration (includes workers pool)
├── tsconfig.json         # TypeScript configuration
└── .env.example          # Documents all env vars the Worker reads
```
