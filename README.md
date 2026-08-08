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

Run the Vitest suite (unit + integration tests):

```sh
npm test
```

Watch mode:

```sh
npm run test:watch
```

## Example implementation

By running this project you can walk through both verification flows: a full-page redirect or an iframe overlay.

Standalone example integrations in various programming languages live in the `example` folder. A MIT-licensed alternative for the example code is available at [Godotcam/goCamOpenSourceExamples](https://github.com/Godotcam/goCamOpenSourceExamples).

## Project structure

```
.
├── src/                  # Worker source (routes, lib, middleware, templates, durable objects)
│   ├── routes/           # HTTP route handlers
│   ├── lib/              # Pure helpers (encryption, url validation, parse, etc.)
│   ├── middleware/        # Session cookie signing/verification
│   ├── templates/        # HTML templates (rendered as strings)
│   └── durable-objects/  # Durable Object definitions (SQLite-backed)
├── app/frontend/         # Static assets served by the Worker (img, css, js)
├── wrangler.jsonc        # Cloudflare Workers configuration (bindings, assets)
├── vitest.config.ts      # Test configuration
├── tsconfig.json         # TypeScript configuration
└── docs/                 # Plans and additional documentation
```
