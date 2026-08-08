# Code Quality & Correctness Review

Target: `goCamCloudflare` — Cloudflare Workers age-verification app (TypeScript, `strict: true`).
Scope: ~1730 lines across 15 files in `src/`. No tests, no lint, no CI.

Each candidate finding below was verified against the actual code. New findings follow in their own section. All line citations are `file:line` and were read in full before assessment.

## Summary (counts)

| Category | Count |
|---|---|
| Candidate findings verified | 11 of 12 (1 refuted, 1 partial) |
| New findings added | 9 |
| Critical | 3 |
| High | 7 |
| Medium | 8 |
| Low | 4 |
| **Total** | **22** |

Verified candidates: 2 Critical, 4 High, 5 Medium, 1 Low.
New findings: 1 Critical, 3 High, 3 Medium, 3 Low.

The single most important finding is **[Critical] PII leak via client-visible DO 500 response** (`verification-session.ts:205`) combined with the **[Critical] `/callback` logs full decrypted PII to console + Analytics Engine** (`routes/index.ts:190,194`). Either one alone is a privacy/data-handling defect; together they mean the same user PII (IP, userData, callback payload) is both echoed to untrusted HTTP clients and shipped to logs/datasets that may have broad read access.

---

## Findings

### [CRITICAL] DO 500 response leaks `String(err)` to the client
- **Status:** Verified
- **Location:** `src/durable-objects/verification-session.ts:203-206`
- **Description:** Every unhandled exception inside the DO `fetch` switch is returned verbatim to the caller:
  ```ts
  } catch (err) {
      console.error('DO error:', err);
      return Response.json({ error: String(err) }, { status: 500 });
  }
  ```
  The DO handles JSON parsing (`request.json()` at lines 155, 161, 176, 181, 186, 191, 196), SQLite SQL (`storage.sql.exec`), and WebCrypto decrypt. `String(err)` on these can surface: SQLite error text (driver internals, schema/column names), the raw encrypted/hex payload being processed, file/key identifiers, or stack frames. The caller is the Worker, which forwards this body onward — and the Worker itself has a catch-all that returns a plain `Internal Server Error` string (`src/index.ts:98-101`), but the DO error body is returned through `callDoJson` which **throws** on the `error` field (`routes/result.ts:47-49`, `routes/token.ts:41-43`), and those throws are in some branches swallowed and in others surfaced. There is no path that strips the DO error before it reaches a client response in the error cases.
- **Impact:** Information disclosure to an untrusted request sender. For an attacker sending crafted `d` payloads, the differential between "decryption failed" and "SQLite constraint" errors is itself an oracle.
- **Minimal fix:** Return a generic message to the client; keep detail server-side only.
  ```ts
  console.error('DO error:', err);
  return Response.json({ error: 'internal_error' }, { status: 500 });
  ```

### [CRITICAL] `/callback` logs full decrypted PII to console and Analytics Engine
- **Status:** Verified
- **Location:** `src/routes/index.ts:190` (console) and `src/routes/index.ts:194-198` (Analytics Engine)
- **Description:** The callback handler logs the entire request body with no field filtering:
  ```ts
  console.log('Callback received:', JSON.stringify(body));
  ...
  env.ANALYTICS.writeDataPoint({
      blobs: ['callback_received', JSON.stringify(body).substring(0, 256)],
      ...
  });
  ```
  Per the DO `dispatchCallback` (`verification-session.ts:472-485`), the callback body is a URL-encoded form containing `userData` (the partner's color config plus any user identifier), `ip` (the end user's real `CF-Connecting-IP`), `websiteHostname`, `sessionId`, `idCountry/idState/idType`, and `errorCode`. The first 256 chars of that JSON go to an Analytics Engine dataset (`gocam_events`) as a blob. Analytics Engine datasets are typically queried via SQL APIs and retained long-term — this is the wrong place to ship raw user identifiers and IPs.
- **Impact:** PII / personal data exfiltration into logs and a long-lived analytics store; likely violates the data-minimization posture the rest of the app claims (the token-index template even asserts "No data, no videos and no pictures are sent to our servers" at `templates/token-index.ts:199`). Legal/privacy risk under GDPR-style regimes.
- **Minimal fix:** Log only non-identifying fields (`sessionId`, `stateInt`, `errorCode`, `websiteHostname`). Drop the `body` blob from the Analytics Engine write entirely, or hash/truncate IPs before any persistence.

### [HIGH] Pervasive `any` typing defeats the value of `strict: true`
- **Status:** Verified
- **Location:** Worst offenders:
  - `src/lib/encryption.ts:80,97,110,112` — `decryptString` returns `Promise<any>` and `base64DecodeString` returns `any`. Every consumer of decrypted data is therefore untyped.
  - `src/lib/response.ts:7` — `successResponse(data: Record<string, any>)`.
  - `src/routes/result.ts:62,145,245,279` — `body: any`, `endResult: any`, `checkResult: any`.
  - `src/routes/token.ts:130,167` — `payloadParsed: any`, `userAgent: any`.
  - `src/routes/index.ts:141,156,178` — `body: any`, `payloadParsed: any`.
  - `src/durable-objects/verification-session.ts:48-68` — `SessionData.userData: any`, `http.paramList: any`.
  - `src/templates/token-index.ts:17,19` — `partnerColorConfig: any`, `deviceInfo: any`.
- **Description:** Because `decryptString` is the root `any` source, none of the decrypted payload fields (`verificationResult.stateInt`, `httpParamList.verificationTypeList`, `userData.colorConfig`, …) are checked by the compiler. The `as` casts on DO request bodies (`verification-session.ts:155,161,176,…`) are unchecked assertions on `any` from `request.json()`, so a malformed DO request produces silently-wrong runtime behavior rather than a type error. `strict: true` is effectively performing no work on the data path that matters most.
- **Impact:** Real bugs hide here. For example `routes/result.ts:148` passes `stepIp: stepId` (the result of `parseInt`) into the DO `end` action typed as `stepIp: number`, but `stepId` can be `NaN` (see dedicated finding below) and the type system gives no warning because the surrounding context is `any`.
- **Minimal fix:** Define and use interfaces for the encrypted payload (`DecryptedPayload`), the DO action request/response shapes, and the cookie session. Type `decryptString` as `Promise<DecryptedPayload>` once the schema is pinned. Replace `body: any` with parsed-and-validated shapes (zod or hand-rolled guards). This is the highest-leverage single change in the codebase.

### [HIGH] `parseInt` without radix and without NaN guard
- **Status:** Verified (radix concern is minor; NaN concern is real)
- **Location:** `src/routes/result.ts:81-82,180-182` (six call sites)
  ```ts
  const stepId                     = parseInt(body.stepId || '0');
  const deviceLocationVerification = parseInt(body.deviceLocationVerification || '0');
  ...
  const errorCode                  = parseInt(body.errorCode || '0');
  ```
- **Description:** The missing radix is a style/lint nit (modern engines treat base-10 prefixes correctly). The real problem is the absent NaN guard. `body` is `any` from the parsed JSON or form. If a client sends `"stepId": "abc"` or `"stepId": ["x"]` (the `|| '0'` only fires for `null`/`undefined`/`''`, not for non-numeric strings), `parseInt` returns `NaN`. Trace:
  - `isValidStep(NaN)` returns `false` (`verification-session.ts:91-93`, `Array.includes` uses strict equality) → the `/result/success` and `/result/fail` handlers return error code 30007/30011. That path is safe.
  - But `deviceLocationVerification === DEVICE_LOCATION_VERIFICATION_INTERNAL` (`result.ts:133,233`) becomes `NaN === 0` → `false`, so the token check is silently **skipped**. An attacker who can otherwise reach `/result/success` with a valid session cookie bypasses the `successKey`/`failKey` token verification by sending a non-numeric `deviceLocationVerification`. The session must still exist (cookie required), so impact is bounded, but the security gate was intended to be on this field.
  - `errorCode` NaN flows into `sessionResult.errorCode` and the DO `end` action; downstream `String(NaN)`/JSON serialization is harmless but semantically wrong.
- **Impact:** A field that gates a token check can be made to evaluate as "not internal verification" by sending garbage, skipping the token comparison. The fail/success DO `end` then proceeds.
- **Minimal fix:**
  ```ts
  const stepId = Number.isFinite(Number(body.stepId)) ? Number(body.stepId) : 0;
  ```
  or a small `parseIntSafe(v, def=0)` helper. Apply to all six sites.

### [HIGH] `escapeHtml` omits single-quote; `base.ts` JSON-in-script omits U+2028/U+2029
- **Status:** Verified (risk is context-dependent; partly low, partly medium)
- **Location:**
  - `src/templates/home.ts:250-256` and `src/templates/token-error.ts:29-35` — escape `& < > "` but not `'`.
  - `src/templates/base.ts:17` and `src/templates/token-embed-check.ts:14` — `JSON.stringify(js).replace(/</g, '\\u003c')`. No escaping of U+2028 LINE SEPARATOR or U+2029 PARAGRAPH SEPARATOR.
- **Description:**
  - **HTML text context (`token-error.ts:20`, `home.ts:239`):** The current `escapeHtml` is adequate. The values interpolated are `msg` (a server-controlled error string from `AvsResponse.errorResponse`) and `nodeEnv` (hardcoded `'production'` at `routes/index.ts:25`). Not user-controlled today; low XSS risk. Missing `'` escape is irrelevant for text content.
  - **Single-quote attribute context:** No template currently interpolates into a single-quoted attribute, so the missing `'` has no live exploit. Low risk, but the helper is generic and reusable — the next person to add `${escapeHtml(userInput)}` inside `value='…'` will introduce an XSS. Add `'` → `&#39;` defensively.
  - **Script JSON context (`base.ts:17`, `token-embed-check.ts:14`):** `JSON.stringify` followed by only `<` replacement is the standard pattern and is safe against `</script>` breakout. U+2028/U+2029 are line separators that are valid JSON but invalid in JavaScript string literals pre-ES2019. Modern browsers (ES2019+) accept them, so for current browsers this is not exploitable. It would matter for very old runtimes; given Workers serves modern clients only, risk is low. The bigger gap: the JSON blob in `token-index.ts` is fed to client JS via `JSON.parse(document.getElementById('app-data').textContent)` (implied), and it contains `deviceInfo` (full `UAParser` output) and `countryAgeMajority` — none of these are attacker-controlled at render time, so no current XSS.
- **Impact:** No live XSS today, but the escaping helpers are a foot-gun for the next contributor.
- **Minimal fix:** Add `'` → `&#39;` to both `escapeHtml` functions. Optionally also escape `>` (already done) and consider a shared `escapeHtml` helper in one place (see DRY finding). For script JSON, replace U+2028/U+2029 as well:
  ```ts
  const jsDataJson = JSON.stringify(js)
      .replace(/</g, '\\u003c')
      .replace(/\u2028/g, '\\u2028')
      .replace(/\u2029/g, '\\u2029');
  ```

### [HIGH] Body parsing silently swallows malformed input to `{}`
- **Status:** Verified
- **Location:**
  - `src/routes/result.ts:62-73` — wraps the entire JSON-or-form parse in `try { … } catch { body = {}; }`.
  - `src/routes/index.ts:181,183-187` — `/callback` handler: `try { body = await request.json(); } catch { body = {}; }` and the same for `formData`.
  - `src/routes/index.ts:140-148` — `/validateVerificationPayload` does NOT wrap `request.json()`; an invalid JSON body throws and propagates to `index.ts:98` catch-all, returning a generic 500.
- **Description:** A malformed JSON request to `/result/*` or `/callback` is indistinguishable from a well-formed empty body. The handler then proceeds: in `/result/success`, `body = {}` → `stepId = 0`, falls through `isValidStep(0)` → false → returns 30007. Bounded. But the silent swallow masks abusive/malformed traffic from monitoring and from any future telemetry; an attacker can probe with garbage and get structured error codes back instead of a 400.
- **Impact:** Defensive obscurity. No correctness bug today, but the asymmetry (`/validateVerificationPayload` throws 500 on bad JSON, `/result/*` silently empties) is inconsistent and surprising.
- **Minimal fix:** Return a `400` with a clear error code on parse failure for `/result/*` and `/callback` rather than continuing with `{}`. At minimum, log the parse failure distinctly from an empty body.

### [HIGH] Stale README documents nonexistent npm scripts
- **Status:** Verified
- **Location:** `README.md:47,51,93,97,101,105,109,113,117,121` vs `package.json:7-14`.
- **Description:** README instructs users to run:
  - `npm run startDev`, `npm run startProd` (lines 47, 51)
  - `npm run build`, `npm run buildJsBackend`, `npm run buildJsFrontend`, `npm run buildCssFrontend` (lines 93, 97, 101, 105)
  - `npm run watch`, `npm run watchJsBackend`, `npm run watchJsFrontend`, `npm run watchCssFrontend` (lines 109, 113, 117, 121)

  The actual `package.json` scripts are: `dev`, `deploy`, `build:css`, `build:frontend`, `tail`, `types`. None of the README commands exist. The README also still describes the project as Node.js/Express with Twig templates and an `app/backend` directory (lines 34, 65, 70, 73, 77, 81, 85) — this is the pre-Workers codebase. The "Project structure" section (lines 63-85) is entirely wrong for the current layout.
- **Impact:** A new contributor cannot run the project from the README. The documented `cp .env.example .env` flow (line 29) is also not how Workers secrets work (`wrangler secret put` / `.dev.vars`). Severe onboarding friction; the README is actively misleading.
- **Minimal fix:** Rewrite the Run/Develop/Project-structure sections to reflect `npm run dev` / `npm run deploy` / `npm run types`, the Workers secret model, and the `src/` layout. Or add a clear "this is a port in progress" notice pointing at `wrangler.jsonc`.

### [MEDIUM] Duplicate `callDoJson<T>` helper in two route files
- **Status:** Verified (byte-for-byte identical)
- **Location:** `src/routes/result.ts:27-52` and `src/routes/token.ts:21-46`.
- **Description:** The two functions are identical character-for-character (same signature, same JSON-parse try/catch, same `!response.ok || json.error` check, same error strings). This is a DRY violation with concrete drift risk: a fix to error handling (e.g. logging the DO response body, or changing the throw to include status) must be applied in two places, and the candidate list above already shows the DO 500 error message is a real concern that this helper propagates.
- **Impact:** Maintenance hazard. No correctness bug today.
- **Minimal fix:** Extract to `src/lib/do.ts` (or `src/middleware/do.ts`):
  ```ts
  export async function callDoJson<T>(
      stub: DurableObjectStub,
      action: string,
      body: Record<string, unknown>,
  ): Promise<T> { /* single implementation */ }
  ```
  Import from both route files.

### [MEDIUM] Module-level mutable singletons cache for the isolate lifetime
- **Status:** Verified (all three exist)
- **Location:**
  - `src/config.ts:24,27` — `_cachedConfig: AppConfig | null`. Once set, never invalidated.
  - `src/lib/encryption.ts:10` — `keyCache = new Map<string, CryptoKey>()`.
  - `src/middleware/session.ts:11` — `hmacKeyCache = new Map<string, CryptoKey>()`.
- **Description:** All three persist for the Worker isolate lifetime. `keyCache` and `hmacKeyCache` are keyed by the key string, so rotating `ENCRYPTION_KEY` (a new value via `wrangler secret put`) does not invalidate the old `CryptoKey` for the running isolate — but a new deployment creates a new isolate anyway, so the practical risk is low. `_cachedConfig` is the subtler one: it captures `env.ENCRYPTION_KEY` once, so any in-isolate change to the env (unusual but possible during testing with `wrangler dev --var`) would be ignored. It also captures `cacheBuster: Date.now()` (line 53) once per isolate, which is the intended behavior for cache-busting but means the value is stable for the isolate's lifetime, not per-deploy.
- **Impact:** Low correctness risk in production. The main hazard is testing/dev surprise. The maps grow unboundedly only if many distinct keys are used (not the case here).
- **Minimal fix:** Acceptable as-is for production. Add a comment documenting the isolate-lifetime semantics. If key rotation without redeploy becomes a requirement, switch to a versioned cache (key string + version counter).

### [MEDIUM] `successResponse` mutates its argument
- **Status:** Verified (benign in practice today)
- **Location:** `src/lib/response.ts:7-12`:
  ```ts
  static successResponse(data: Record<string, any> = {}): { content: Record<string, any> } {
      data.success = 1;
      return { content: data };
  }
  ```
- **Description:** The function writes `success = 1` onto the caller's object. All current call sites pass a fresh object literal (`routes/index.ts:132,171`, `routes/result.ts:165,260,281`) or the default `{}` (`routes/index.ts:203`), so no shared/frozen object is affected today. But the mutation is surprising: a caller who passes a reused config object, or a frozen object (`Object.freeze`), would either see silent state corruption or a strict-mode `TypeError`.
- **Impact:** No live bug. Foot-gun for future callers; violates the principle of least surprise.
- **Minimal fix:**
  ```ts
  static successResponse(data: Record<string, any> = {}) {
      return { content: { ...data, success: 1 } };
  }
  ```

### [MEDIUM] `callDoJson` error handling — thrown errors lose the DO response body
- **Status:** Verified
- **Location:** `src/routes/result.ts:40-52` and `src/routes/token.ts:34-46` (the shared helper), plus caller catch sites at `routes/result.ts:113-116,213-216` and `routes/token.ts:118-120,159-165`.
- **Description:** When the DO returns non-OK or an `error` field, the helper throws `new Error(\`DO action "${action}" failed\`)` and discards the parsed `json` (which may contain a useful `error` field — see the Critical DO-leak finding for why that field is itself sensitive). Callers catch and log only the `Error` message, not the DO body:
  - `routes/result.ts:114` logs `'DO getRequestSession error:', err` — `err.message` is the generic string.
  - `routes/token.ts:119,160` log `'DO start error:' / 'DO storeRequestSession error:'` with the same generic message.
  - Critically, the `end` and `updateState` calls in `routes/result.ts:125,136,225,236,145,245` are **not wrapped in try/catch** — a throw there propagates to `index.ts:98` and returns a plain 500 to the client. The user has already been told (via Set-Cookie in the success path) nothing; they just get a 500 with no body. This is acceptable but means a transient DO failure on `end` loses the verification result with no retry signal.
- **Impact:** Debuggability gap (errors are over-generic) and one unhandled-throw path on `end`/`updateState` that yields a bare 500.
- **Minimal fix:** Have the helper include the DO `status` (not the body) in the thrown error: `throw new Error(\`DO "${action}" failed (HTTP ${response.status})\`)`. Wrap the `end` call in `routes/result.ts:145` and `245` in try/catch to return a structured error code (e.g. reuse 30010) instead of a bare 500.

### [LOW] `nodejs_compat` absent — but not currently required
- **Status:** Refuted as a bug (correctly absent)
- **Location:** `wrangler.jsonc` has no `compatibility_flags`; `ua-parser-js` is the sole runtime dependency (`package.json:30`).
- **Description:** A grep of `src/` for Node-specific APIs (`Buffer`, `process`, `require`, `fs`, `path`, `stream`, `os`, Node `crypto`, `url.parse`, `setImmediate`) finds **no usage** beyond Web-Platform primitives (`crypto.subtle`, `crypto.randomUUID`, `crypto.getRandomValues`, `btoa`/`atob`, `setTimeout`, `fetch`, `URL`, `URLSearchParams`, `TextEncoder`/`TextDecoder`, `AbortController`) — all native to the Workers runtime. `ua-parser-js` is a pure-JS string parser with no Node dependency. The `compatibility_date` of `2025-04-01` enables the current defaults.
- **Impact:** None. The flag is correctly omitted.
- **Minimal fix:** None. Optionally add a one-line comment in `wrangler.jsonc` noting that `nodejs_compat` is deliberately off and that adding a Node-dependent dependency would require enabling it.

### [LOW] `console.log`/`console.error` enumeration — multiple leaks of decrypted detail
- **Status:** Verified
- **Location:** Every `console.*` call in `src/`:
  - `src/durable-objects/verification-session.ts:204` — `console.error('DO error:', err)` — logs full error incl. potentially the payload/key context.
  - `src/durable-objects/verification-session.ts:504` — `console.log('Callback data success!')` — benign.
  - `src/durable-objects/verification-session.ts:509` — `console.log('Callback dispatch error:', err)` — may include the callback URL or response status.
  - `src/index.ts:99` — `console.error('Unhandled error:', err)` — top-level, may log anything.
  - `src/routes/index.ts:190` — **the PII leak covered by the Critical finding above.**
  - `src/routes/result.ts:114,214` — `console.error('DO getRequestSession error:', err)` — generic.
  - `src/routes/token.ts:119,160` — `console.log('DO start/storeRequestSession error:', e)` — generic, but `storeRequestSession` failure could log context referencing the payload hash.
- **Description:** Workers `console.*` output goes to `wrangler tail` and the Workers Logs product, which is typically broader-audience than application logs. The only statement that demonstrably leaks user data is `routes/index.ts:190` (the Critical finding). The rest are low-severity but should be audited before enabling log shipping to a third party.
- **Impact:** One data leak (see Critical), remainder is operational hygiene.
- **Minimal fix:** Remove/redact `routes/index.ts:190`. For the others, ensure no future change starts logging `body`, `payload`, or `sessionData` objects wholesale.

---

## New findings (beyond candidates)

### [CRITICAL] `verifySessionId` redundant byte arrays + comment claims timing-safety the code doesn't deliver
- **Status:** New
- **Location:** `src/middleware/session.ts:59-103`.
- **Description:** The function is correct in *outcome* but the implementation is misleading and contains dead code:
  ```ts
  // line 67-68
  const expectedSigned = await signSessionId(sessionId, key);
  const expectedSigHex = expectedSigned.substring(expectedSigned.lastIndexOf('.') + 1);
  // line 70-74
  const enc = new TextEncoder();
  const a = enc.encode(expectedSigHex);
  const b = enc.encode(signatureHex);
  if (a.byteLength !== b.byteLength) return null;
  ```
  `a` and `b` are computed and length-checked but **never compared** — the actual verification is done later by `crypto.subtle.verify('HMAC', cryptoKey, sigBytes, enc.encode(sessionId))` (lines 95-100). The length check leaks nothing and the `verify` is genuinely constant-time, so the security property holds. But: (a) the comment on line 66 ("Timing-safe comparison: re-sign and compare raw bytes") describes code that isn't there; (b) `expectedSigHex` is computed and discarded; (c) `signSessionId` is called purely to discard its result, wasting a crypto operation per verification.
- **Impact:** No security flaw, but the misleading comment + dead code is a review trap — the next reader may "fix" the dead comparison and accidentally replace the real `verify`. Wasted HMAC sign per request.
- **Minimal fix:** Delete lines 66-74 (the `expectedSigned`/`expectedSigHex`/`a`/`b` block) and rely solely on `crypto.subtle.verify`. Fix the comment to describe what the code does.

### [HIGH] `callDoJson` is invoked **without** try/catch for `end`, `updateState`, `storeRequestSession` (partial) — unhandled throws
- **Status:** New (extends candidate #12)
- **Location:** Unprotected `callDoJson` calls:
  - `src/routes/result.ts:125-128` (`updateState` on max-duration expiry, success path)
  - `src/routes/result.ts:136-139` (`updateState` on token mismatch, success path)
  - `src/routes/result.ts:145-153` (`end` on success)
  - `src/routes/result.ts:225-228` (`updateState` on fail path)
  - `src/routes/result.ts:236-239` (`updateState` on token mismatch, fail path)
  - `src/routes/result.ts:245-253` (`end` on fail)
  - `src/routes/result.ts:279` (`isPayloadValidated`)
  - `src/routes/token.ts:148-158` (`storeRequestSession` — this one IS caught at 159).
- **Description:** With the exception of `storeRequestSession`, none of the above are wrapped. A thrown error propagates to the top-level `index.ts:98` catch, which returns a plain `Internal Server Error` 500 with no JSON body. For `/result/success` this means the user's browser receives an opaque 500 even though the session was already half-ended (the `updateState` on line 125 may have succeeded before `end` on line 145 threw, or vice versa). The client cannot distinguish "transient DO failure" from "session genuinely invalid".
- **Impact:** Poor error UX and no retry semantics; partial state writes possible in the two-step `updateState`+`end` sequences.
- **Minimal fix:** Wrap each unprotected `callDoJson` in try/catch; on failure return a structured `AvsResponse.errorResponse(...)` with a defined code rather than letting it escape to the 500 catch-all. Consider making `updateState`+`end` atomic from the caller's perspective (or document that partial writes are tolerable).

### [HIGH] `config.cookie` fields are hardcoded and inconsistent with the session cookie
- **Status:** New
- **Location:** `src/config.ts:47-51` (`httpOnly: false`, `secure: true`, `maxAge: 30 * 24 * 60 * 60 * 1000`) vs `src/middleware/session.ts:159` (`HttpOnly; SameSite=Lax; Max-Age=1200`).
- **Description:** Two cookies are set with different policies and the `config.cookie` block is misleading:
  - `config.cookie.httpOnly = false` is used at `routes/result.ts:163` to decide whether to emit `; HttpOnly` for the `isAgeVerified` cookie — so that cookie is readable from client JS by design (the iframe-check page reads it via `parseCookies` server-side, but the client also reads it for the embed-check UI). That's intentional.
  - But `config.cookie.maxAge = 30 * 24 * 60 * 60 * 1000` is **in milliseconds** (30 days in ms). At `routes/result.ts:163` it's divided by 1000 before being put in the cookie: `Max-Age=${config.cookie.maxAge / 1000}` — correct. But it's the only place the unit conversion happens, and the value stored in config is in ms while cookie `Max-Age` is in seconds. This is a unit-conversion foot-gun.
  - The session cookie at `session.ts:159` hardcodes `Max-Age=1200` (20 minutes, seconds) — bypassing `config.cookie` entirely. So the two cookies have wildly different lifetimes (30 days vs 20 minutes) with no shared source of truth.
  - `config.cookie.secure = true` is always true; the `config.cookie.secure ? '; Secure' : ''` ternary at `result.ts:163` is dead branch (always emits `; Secure`). In local dev over `http://localhost` a `Secure` cookie will be **dropped by the browser**, silently breaking the verification flow for anyone following the README's localhost advice.
- **Impact:** (1) localhost dev silently fails because `Secure` cookies aren't stored over http. (2) The ms-vs-s unit mismatch is a future bug waiting to happen. (3) Two cookies with unrelated lifetimes and no shared config.
- **Minimal fix:** Drive both cookies from `config.cookie`. Make `secure` env-driven (`env.ENVIRONMENT !== 'development'` or a `LOCALHOST` flag). Add a unit comment next to `maxAge`. Document the differing lifetimes if intentional.

### [MEDIUM] `getSessionContextFromRequest` returns a session even after cookie expiry; no server-side TTL check on the request-session
- **Status:** New
- **Location:** `src/middleware/session.ts:135-147` (cookie verify) and `src/durable-objects/verification-session.ts:441-446` (retention cleanup).
- **Description:** The session cookie has `Max-Age=1200` (20 min). The DO `request_sessions` table is cleaned of rows older than `REQUEST_SESSION_RETENTION_TIME = 2h` (`verification-session.ts:44`). Between 20 min and 2h, the browser has dropped the cookie (so no issue), but if a cookie is replayed (e.g. captured and re-sent), the DO will still find the row for up to 2h. The HMAC on the cookie prevents tampering but not replay. The result-route `MAX_TEST_DURATION` check (`routes/result.ts:15,123,223`) is the only server-side freshness gate, and it reads `reqSession.accessTime` which is set at token-page render. So the test-duration gate is enforced; the request-session retention (2h) is just housekeeping. The asymmetry (20-min cookie vs 2h server retention) is not a vulnerability but is surprising.
- **Impact:** Low. Worth a comment documenting the relationship.
- **Minimal fix:** Align retention with cookie Max-Age (or document why 2h is intentional for replay-recovery). Add a comment.

### [MEDIUM] `UA` parser exception falls back to raw string typed as `any`, then serialized into client JSON
- **Status:** New
- **Location:** `src/routes/token.ts:167-173`:
  ```ts
  let userAgent: any = '';
  ...
  try { userAgent = UAParser(uaString); } catch { userAgent = uaString; }
  ```
  Then `deviceInfo: userAgent` at `routes/token.ts:191` flows into the `token-index` template's `js` blob (`templates/token-index.ts:19`) and is emitted as JSON-in-script by `base.ts:17`.
- **Description:** The fallback is fine functionally, but `userAgent: any` means a thrown `UAParser` (unlikely but possible on pathological input) silently turns `deviceInfo` from an object into a string, changing the shape the client JS receives. The client may then do `deviceInfo.browser.name` and crash. No type guard recovers this.
- **Impact:** Low correctness risk; client-side breakage on pathological UAs.
- **Minimal fix:** Type `userAgent` as the `UAParser.IResult`-ish shape or `string`; log the catch.

### [MEDIUM] `endResult.payload` truthiness check differs between success and fail handlers
- **Status:** New
- **Location:** `src/routes/result.ts:155` (`if (!endResult || !endResult.payload)`) vs `src/routes/result.ts:255` (`if (!endResult || typeof endResult.payload !== 'string')`).
- **Description:** The two handlers calling the same DO `end` action validate the response differently. The success path accepts any truthy `payload`; the fail path requires a `string`. The DO always returns `{ payload: string } | null` (`verification-session.ts:286,340-342`), so both checks happen to work, but the inconsistency is a smell and the looser success check would accept `{ payload: 42 }` without complaint.
- **Impact:** No live bug; maintenance hazard.
- **Minimal fix:** Use the same `typeof endResult.payload !== 'string'` check in both. Better: have `callDoJson<{ payload: string } | null>` and let TS enforce it once `any` is removed.

### [MEDIUM] `_cachedConfig` caches `cacheBuster: Date.now()` once per isolate — defeats intent of cache-busting on deploy
- **Status:** New (extends candidate #6)
- **Location:** `src/config.ts:53`.
- **Description:** The cache-buster is intended to version-bust static asset URLs (`?${cacheBuster}` in templates). By capturing `Date.now()` into `_cachedConfig`, the value is fixed for the isolate's lifetime. A long-lived isolate will serve the same cache-buster across deploys until the isolate is recycled, so clients may see stale JS/CSS after a deploy that doesn't also rotate isolates. In practice Workers recycle isolates on deploy, so this is usually fine — but it's an assumption worth not making silently.
- **Impact:** Possible stale-asset serving in edge cases (isolate reuse across deploys).
- **Minimal fix:** Compute `cacheBuster` per-request (cheap) or derive it from a build-time constant (e.g. git SHA injected via Wrangler `vars`). Per-request is simplest:
  ```ts
  cacheBuster: Date.now(),
  ```
  computed inside `getConfig` after the cache check, or remove the cache and rebuild config per request (config build is cheap).

### [LOW] `config.test.maxDuration` is defined but unused — actual constant lives in `routes/result.ts`
- **Status:** New (dead config)
- **Location:** `src/config.ts:11-13,43-45` (`test.maxDuration: 20 * 60 * 1000`) vs `src/routes/result.ts:15` (`const MAX_TEST_DURATION = 20 * 60 * 1000`).
- **Description:** The config exposes `test.maxDuration` but the route hardcodes its own `MAX_TEST_DURATION`. The two happen to be equal (20 min); if someone changes the config expecting the route to honor it, nothing happens.
- **Impact:** Dead/misleading config field.
- **Minimal fix:** Either consume `config.test.maxDuration` in the route, or delete the field from `AppConfig`.

### [LOW] Dead branch: `config.cookie.secure` is always `true`
- **Status:** New (extends cookie finding)
- **Location:** `src/config.ts:49` (`secure: true`) and `src/routes/result.ts:163` (`${config.cookie.secure ? '; Secure' : ''}`).
- **Description:** The ternary never takes the false branch. See the cookie finding for the localhost impact.
- **Impact:** Dead code; masks the localhost-dev breakage.
- **Minimal fix:** Make `secure` env-driven as described in the cookie finding.

### [LOW] `AvsEncryption` hex parsing uses `parseInt` without explicit radix and without NaN guard
- **Status:** New
- **Location:** `src/lib/encryption.ts:37` (`parseInt(hex.substring(i, i + 2), 16)`) and `src/middleware/session.ts:92` (`parseInt(signatureHex.substring(i, i + 2), 16)`).
- **Description:** Unlike the route `parseInt` calls (candidate #3), these correctly pass radix `16`. No NaN guard, but malformed hex would only arise from a malformed ciphertext/HMAC, which would fail downstream crypto ops anyway. Flagged only for completeness and consistency with a future lint rule.
- **Impact:** Negligible.
- **Minimal fix:** None required; optionally add a hex-character validation if hardening.

---

## Notes on what was checked and found clean

- **Routing** (`src/index.ts`): pathname-based dispatch is correct; the `startsWith('/token')` / `startsWith('/result')` branches are checked before the exact-match index branch, which is the right order (no shadowing). OPTIONS preflight and the security-header wrapper are sound. The 404 fallback correctly tries `env.ASSETS.fetch` first.
- **HMAC cookie signing** (`src/middleware/session.ts:36-54`): `signSessionId` is correct and uses `crypto.subtle.sign`. The `verifySessionId` outcome is correct despite the dead code (see new finding).
- **Encryption** (`src/lib/encryption.ts`): AES-CBC with a random 16-byte IV per encrypt, IV prepended in hex. The split-on-`:` logic at line 83 correctly handles the `ivHex|:encryptedHex` format. `importKey` caching is sound. Note: AES-CBC is malleable and unauthenticated; for a security review that would be flagged, but it is out of scope for this quality/correctness pass.
- **DO schema** (`verification-session.ts:110-140`): tables, indexes, and parameterized queries are well-formed; no SQL injection in the parameterized paths. `getById` and `getRequestSession` correctly return `null` when no row.
- **`AvsRandom`** (`src/lib/random.ts`): uses `crypto.getRandomValues`, correct hex encoding, slice to requested length.
