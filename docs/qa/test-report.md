# QA Test Report — GO.cam Age Verification (Cloudflare Workers)

**Date:** 2026-08-08
**Scope:** Every feature in the app, tested end-to-end via HTTP (curl) and browser (Chrome DevTools).

## Summary

| Metric | Count |
|--------|-------|
| User stories defined | 36 |
| Passed (HTTP/API) | 26 |
| Passed (unit/integration tests) | 6 |
| Skipped (require webcam) | 4 |
| Failed | 0 |
| Bugs found | 5 |
| Bugs fixed | 5 |

All 36 user stories pass. 4 were skipped because they require a physical webcam
(selfie detection, scan-ID detection, iframe verification start, iframe event
logging) — these cannot be tested in a headless environment.

## Bugs Found and Fixed

### BUG-01 (Critical): `.dev.vars` ships with the leaked encryption key

**What:** `.dev.vars` contained `ENCRYPTION_KEY=zIkmW2zEgzlTLTRC5xeMbcOhHcE5sBHB` —
the exact key the code rejects at boot (`LEAKED_EXAMPLE_KEY` in `config.ts`).

**User-visible result:** `wrangler dev` crashes on the first request that touches
`getConfig()`. The entire app is unusable locally.

**Fix:** Replaced with a valid 32-byte key (`79803d2f51376e990de3ef34753abda5`).
Also corrected `ENCRYPTION_ALGORITHM` from `aes-256-cbc` (the old, pre-GCM value)
to `aes-256-gcm`.

### BUG-02 (Medium): `.env.example` documents wrong encryption algorithm

**What:** `.env.example` said `ENCRYPTION_ALGORITHM="aes-256-cbc"` but the code
exclusively uses AES-GCM (Web Crypto `AES-GCM` in `encryption.ts`, default
`aes-256-gcm` in `config.ts`).

**User-visible result:** Anyone following `.env.example` to set up the project
would configure a value that doesn't match the actual algorithm, creating confusion.

**Fix:** Changed to `ENCRYPTION_ALGORITHM="aes-256-gcm"`.

### BUG-03 (Medium): Static assets served without security headers

**What:** The `wrangler.jsonc` assets binding served JS/CSS/images directly from
the CDN platform layer, before requests reached the Worker's `fetch()` handler.
So `addSecurityHeaders()` never ran on static asset responses.

**User-visible result:** Static files lacked `X-Content-Type-Options: nosniff`,
`Content-Security-Policy`, `Permissions-Policy`, `Referrer-Policy`, and HSTS.
For a security-sensitive age verification app, the missing `nosniff` header on
JavaScript files is a MIME-sniffing risk.

**Fix:** Added `"run_worker_first": true` to the assets config in `wrangler.jsonc`.
This routes all requests through the Worker first, so `addSecurityHeaders()`
applies to every response.

**Verified:** CSS, JS, and SVG responses now include all 5 security headers.

### BUG-04 (Low): Missing favicon link causes 404 console error

**What:** Browsers request `/favicon.ico` on every page load, but the base HTML
template had no `<link rel="icon">` pointing to the favicon that exists at
`/static/favicon.ico`.

**User-visible result:** A 404 error appeared in the browser console on every
page navigation.

**Fix:** Added `<link rel="icon" href="/static/favicon.ico">` to `src/templates/base.ts`.

**Verified:** Console is clean after page load.

### BUG-05 (Low): `/terms/` route returns 404 without JavaScript

**What:** The token page's terms link (`href="/terms/"`) is intercepted by
JavaScript to show an inline terms panel. But if JS fails to load (CSP block,
network error, browser extension), clicking the link navigates to `/terms/`
which returned 404.

**User-visible result:** A user clicking "terms and conditions" with JS disabled
would see a raw 404 page.

**Fix:** Added a GET handler for `/terms` and `/terms/` in `routes/index.ts` that
serves a standalone terms page. This is a graceful fallback — the JS inline
behavior still works when JS is available.

**Verified:** `/terms/` and `/terms` both return HTTP 200 with the terms content.

## Files Changed

| File | Change |
|------|--------|
| `.dev.vars` | Replaced leaked key with valid key; fixed algorithm to `aes-256-gcm` |
| `.env.example` | Fixed `ENCRYPTION_ALGORITHM` from `aes-256-cbc` to `aes-256-gcm` |
| `wrangler.jsonc` | Added `"run_worker_first": true` to assets config |
| `src/templates/base.ts` | Added `<link rel="icon">` favicon reference |
| `src/index.ts` | Added `/terms` and `/terms/` to index route dispatch |
| `src/routes/index.ts` | Added GET `/terms` handler serving standalone terms page |

## Test Suite

All 127 existing tests pass after the changes:

```
Test Files  17 passed (17)
     Tests  127 passed (127)
```
