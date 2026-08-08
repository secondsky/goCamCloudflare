# Security & Attack Surface Review

Target: `goCamCloudflare` (Cloudflare Worker — browser-based age verification, selfie ML + ID OCR, client-side).
Scope: all of `src/`. Read-only review; no source files were modified.
Method: every claim below was verified against the cited file:line by reading the full surrounding file.

## Summary

Verified counts: **2 Critical, 4 High, 4 Medium, 2 Low** (plus 1 refuted). The two Critical findings (SSRF and verification-bypass) are independent and each alone fully compromises the system's purpose; together they let an attacker mint a valid "over 18" proof for any identity and exfiltrate it to an arbitrary URL while also forcing the Worker to make attacker-directed POSTs.

| # | Severity | Title | Status |
|---|----------|-------|--------|
| 1 | Critical | SSRF via attacker-controlled `callbackUrl` | Verified |
| 2 | Critical | Verification bypass via `deviceLocationVerification != 0` | Verified |
| 3 | Medium | CORS `*` on every response | Partially verified (low real impact) |
| 4 | High | Missing security headers (no CSP / frame-ancestors / etc.) | Verified |
| 5 | Medium | `isAgeVerified` cookie non-HttpOnly + replayable | Verified |
| 6 | Low | CSRF surface is minimal | Refuted (as a meaningful risk) |
| 7 | High | No rate limiting | Verified |
| 8 | High | AES-CBC without MAC enables ciphertext tampering / padding oracle | Verified |
| 9 | Low | `/result/isSuccess` is a state-disclosure oracle | Verified |
| 10 | Medium | Trust of `CF-Connecting-IP` / `request.cf` with insecure defaults | Verified |

New findings beyond the candidate list are in the final section.

---

## Findings

### [CRITICAL] 1. SSRF via attacker-controlled `callbackUrl`
- **Status:** Verified
- **Location:** `src/routes/index.ts:46,60-67,90-123` (intake, the only validation is `new URL()`); `src/durable-objects/verification-session.ts:245,302-306,461-511` (stored, then `fetch()`ed server-side).
- **Description:** `/getVerificationPayloadAndUrl` accepts `callbackUrl` from a multipart form. The full validation is:
  ```ts
  // src/routes/index.ts:60-67
  if (typeof callbackUrl !== 'string' || callbackUrl.trim() === '') { ... }
  try { new URL(callbackUrl); } catch { ... }
  ```
  There is no scheme allowlist, no host allowlist, no private-IP/link-local/loopback block, and no DNS-pinning. The value is encrypted into the payload, later decrypted by the Durable Object (`verification-session.ts:245`), and on session end the DO does:
  ```ts
  // src/durable-objects/verification-session.ts:491-498
  const response = await fetch(sessionData.callbackUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: callbackData.toString(),
      signal: controller.signal,
  });
  ```
  The Worker runs on Cloudflare's network; `fetch()` from a Worker can reach cloud metadata endpoints and internal services that are reachable from Cloudflare egress, and can be used to send form-encoded POSTs containing attacker-influenced fields (`userData` JSON, `websiteHostname`, `ip`, `idCountry`, etc.) to any third party.
- **Exploit/Impact:** Anyone can `POST /getVerificationPayloadAndUrl` with `callbackUrl=http://169.254.169.254/latest/meta-data/...` (or an internal admin panel, or a victim third party), then open the returned `/token?d=...` link and complete the flow (see Finding 2 to complete it without doing any real verification). On session end the Worker issues a server-side POST to the attacker-chosen URL. Two concrete abuses: (a) hit cloud metadata / internal-only services from Cloudflare's egress; (b) use the Worker as an open POST-relay to spam/phish third parties with bodies that look like they come from this service. Note the body carries `userData` which is also fully attacker-controlled via the same endpoint, so the relayed content is largely attacker-authored.
- **Minimal fix:** In `/getVerificationPayloadAndUrl`, after parsing `new URL(callbackUrl)`:
  1. Require `u.protocol === 'https:'` (or `'http:'` only if you must).
  2. Resolve the host and reject if it parses to a private/loopback/link-local/multicast range (10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, 100.64/10, 169.254.169.254 specifically, IPv6 `::1`, `fc00::/7`, `fe80::/10`).
  3. Maintain a partner allowlist of permitted callback hostnames and reject anything else. (The product is a per-partner integration, so an allowlist is appropriate, not a burden.)
  4. Use `cf: { resolveOverride }` carefully — better to validate the resolved address is consistent on each call (DNS rebinding).

---

### [CRITICAL] 2. Verification bypass via `deviceLocationVerification` other than 0
- **Status:** Verified
- **Location:** `src/routes/result.ts:82,133-142` (`/result/success`); `src/routes/result.ts:181,233-242` (`/result/fail`); definition `src/routes/result.ts:16` (`DEVICE_LOCATION_VERIFICATION_INTERNAL = 0`).
- **Description:** The secret-key check that is supposed to prove the client actually went through the verification flow is gated on the client-supplied value being exactly 0:
  ```ts
  // src/routes/result.ts:82
  const deviceLocationVerification = parseInt(body.deviceLocationVerification || '0');
  ...
  // src/routes/result.ts:133-142
  if (deviceLocationVerification === DEVICE_LOCATION_VERIFICATION_INTERNAL) {
      if (!(reqSession.successKey && token === reqSession.successKey)) {
          ... return 30009 'Invalid token'
      }
  }
  // falls through to end the session as SUCCESS with no token check
  ```
  `body.deviceLocationVerification` is fully client-controlled. `parseInt('1') === 1`, `parseInt('any-non-zero') !== 0`, so sending `deviceLocationVerification=1` (or any non-zero value, or a string like `"external"`) skips the `successKey`/`failKey` comparison entirely. The default when the field is absent is `'0'` → 0 → check runs, so the bypass requires the attacker to actively send a non-zero value — which is trivial. `/result/fail` has the identical structure (lines 181, 233-242) so a non-zero value also lets an attacker force a fail (less interesting, but confirms the pattern is a systemic gate-misuse).
  The only remaining preconditions to reach the "end as success" path are: a valid `avs-session` cookie (obtained by simply loading any `/token?d=...` page once — `src/routes/token.ts:199`) and a `stepId` in the valid set (`isValidStep`, line 95). Both are trivially satisfiable.
- **Exploit/Impact:** An attacker (including a minor who wants to bypass age verification, or an attacker using Finding 1 to also weaponize SSRF) does:
  1. `POST /getVerificationPayloadAndUrl` to obtain `payload` + `url` (and set `callbackUrl` to their collector).
  2. `GET {url}` once to receive the `avs-session` cookie.
  3. `POST /result/success` with `stepId=1`, `deviceLocationVerification=1`, any `token`. The check at line 133 is skipped; the DO ends the session as `SESSION_STATE_SUCCESS` (`result.ts:145-153`), returns a freshly encrypted `successPayload` and sets the `isAgeVerified` cookie.
  No selfie, no ID, no liveness is ever performed. The returned `successPayload` decrypts to a payload whose `verificationResult.stateInt === 2 (SUCCESS)` and is accepted by `/validateVerificationPayload` (`src/routes/index.ts:167-173`). This is a complete defeat of the product's purpose.
- **Minimal fix:** The `deviceLocationVerification` parameter is server-trustable signal that must not be honored from client input. Either:
  - Remove the `if (deviceLocationVerification === 0)` wrapper entirely and always require the token check (the token was issued server-side in `token.ts:140-141` and is per-session), **or**
  - Drive `deviceLocationVerification` from a server-side source (the signed session cookie / payload), never from `body`.
  The smallest change is to delete lines 133 and 142's `if` guard so the token check always runs. The same fix must be applied at `result.ts:233-242`.

---

### [HIGH] 4. Missing security headers
- **Status:** Verified
- **Location:** `src/index.ts:44-58` (`addSecurityHeaders` — only `Permissions-Policy` and CORS); `src/templates/base.ts:14-43` and `src/templates/token-embed-check.ts:16-31` (HTML shells).
- **Description:** `addSecurityHeaders` sets only `Permissions-Policy` and CORS. There is no:
  - `Content-Security-Policy` (and the page loads remote scripts/styles and renders attacker-influenced JSON into a `<script type="application/json">` — see base.ts:34),
  - `X-Frame-Options` or `frame-ancestors` (the app is explicitly designed to be iframe-embedded; `src/routes/token.ts:75` `/token/iframeRender`, `src/routes/token.ts:56` `/token/iframeCheck`),
  - `X-Content-Type-Options: nosniff`,
  - `Strict-Transport-Security`,
  - `Referrer-Policy`.
  Confirmed by grep across `src/` and `wrangler.jsonc`: none of these header names appear.
- **Exploit/Impact:** Without `frame-ancestors`/`X-Frame-Options`, any third-party site can iframe the verification pages — enabling clickjacking of the "Start verification" / camera-permission grant flow, and letting an attacker drive a victim through the flow. Without CSP, any future reflected/DOM XSS in the loaded vendor JS (jQuery 3.5.1, face-api, tesseract, etc. — `token-index.ts:439-448`) is unmitigated, and there is no defense-in-depth for the JSON-in-script data embedding. Missing `nosniff` lets browsers MIME-sniff JSON responses as HTML in error paths.
- **Minimal fix:** In `addSecurityHeaders` (`src/index.ts:45-58`) add, at minimum:
  ```ts
  newHeaders.set('X-Content-Type-Options', 'nosniff');
  newHeaders.set('Referrer-Policy', 'no-referrer');
  newHeaders.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  newHeaders.set('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; ..."); // tune to actual asset origins
  // frame-ancestors: enumerate the legitimate partner origins; do NOT use * here.
  newHeaders.set('X-Frame-Options', 'DENY'); // or CSP frame-ancestors allowlist — note XFO does not support allowlists well
  ```
  `frame-ancestors` must be a concrete allowlist of partner origins, not `*`, or the iframe-embed model itself becomes the vulnerability.

---

### [HIGH] 7. No rate limiting
- **Status:** Verified
- **Location:** `src/index.ts` (no `[[unsafe.bindings]]` rate-limit binding; none referenced), `wrangler.jsonc` (no `rate_limit` binding), and no in-Worker throttle in any route.
- **Description:** There is no Cloudflare Rate Limiting binding and no in-Worker counter. Every endpoint is unauthenticated, so every cost-incurring operation is unthrottled:
  - `/getVerificationPayloadAndUrl` mints a payload (each call also runs AES + a DO write),
  - `/token?d=...` does a DO `start` + `storeRequestSession` (2 SQLite writes + AES decrypt) per hit,
  - `/result/success` does `getRequestSession` + `end` (2 SQLite ops + AES decrypt + AES encrypt + outbound `fetch`),
  - The Durable Object is keyed by `payloadHash` (= first 64 chars of the encrypted payload, `token.ts:104`), and the same DO can be hammered.
- **Exploit/Impact:** (a) Cost/DoS: an attacker can run up Durable Object read/write request counts and CPU by looping any of the above, since each request is unauthenticated and CORS is `*`. (b) Brute-forcing `successKey`/`failKey` — these are 32 hex chars = 128 bits (`AvsRandom.generateRandomString(32)`, `token.ts:140-141`), so online brute force is infeasible on entropy grounds alone; **but** Finding 2 renders brute-force moot. (c) Unlimited payload minting amplifies Finding 1's SSRF relay.
- **Minimal fix:** Add a Cloudflare Rate Limiting binding in `wrangler.jsonc` (`rate_limit` rules) covering `POST /getVerificationPayloadAndUrl`, `GET /token`, and `POST /result/*`, keyed by `ip_scripthost` or a Turnstile token. Given the app already has no auth, also add Cloudflare Turnstile on `/getVerificationPayloadAndUrl` and `/result/*` to prevent automation.

---

### [HIGH] 8. AES-CBC without integrity (no MAC) — ciphertext tampering / padding oracle
- **Status:** Verified
- **Location:** `src/lib/encryption.ts:55-98` (AES-256-CBC, no GCM, no HMAC); `src/config.ts:36` (default algorithm `aes-256-cbc`); consumed everywhere a payload is trusted after decrypt — most importantly `src/routes/index.ts:156-173` (`/validateVerificationPayload`) and `src/durable-objects/verification-session.ts:215,328`.
- **Description:** All payloads are encrypted as `ivHex|:ciphertextHex` with AES-CBC and no MAC. `decryptString` (`encryption.ts:80-98`) relies solely on CBC padding correctness and `JSON.parse` to "validate" — it has no authenticity check. Two consequences:
  1. **Padding oracle:** any decrypt path that distinguishes "bad padding" from "bad JSON" leaks a classic Vaudenay CBC padding oracle. `/validateVerificationPayload` returns error code `30002` on decrypt failure (`routes/index.ts:159-161`) vs `30003` on a successful decrypt with the wrong `stateInt` (`routes/index.ts:167-169`) — the response differs based on whether padding was valid, which is exactly the side channel needed to decrypt or forge ciphertext block-by-block.
  2. **Bit-flipping on CBC:** because the plaintext is JSON and the IV is attacker-visible (it's the leading hex of the payload), an attacker who knows the rough plaintext layout can flip bits in the IV/previous block to alter the first block's plaintext. The high-value target is `verificationResult.stateInt` — but note that field is appended by the DO on `end` (line 333), so the practical forgery target is `userIpCountry`/`userIpState`/`creationTimestamp` in the original payload, not directly minting a success result. (Minting success is already trivially done via Finding 2.)
- **Exploit/Impact:** An attacker who can submit many `/validateVerificationPayload` requests can use the padding oracle to decrypt any captured payload (e.g. an `isAgeVerified` cookie stolen via Finding 5) and to forge new payloads that pass `/validateVerificationPayload`'s decrypt step with attacker-chosen plaintext (subject to JSON validity). Combined with Finding 2 the forgery is not necessary, but the padding oracle independently lets the encryption be peeled off any captured token.
- **Minimal fix:** Switch to an authenticated scheme — `AES-GCM` via `crypto.subtle` is the smallest change (single algorithm swap in `encryption.ts`), and it gives both confidentiality and integrity. If CBC must stay for back-compat, add a MAC (encrypt-then-MAC, HMAC-SHA256 over `iv||ciphertext`) and verify the MAC before decrypting; also make the error response identical regardless of whether the failure was padding vs JSON (`return AvsResponse.errorResponse(30002, '...')` in both branches — currently the two branches already return the same code in `/validateVerificationPayload`, but `/token` (`token.ts:131-138`) and `endSession`'s decrypt can still distinguish, so unify all failure paths once a MAC exists).

---

### [MEDIUM] 3. CORS `Access-Control-Allow-Origin: *` on every response
- **Status:** Partially verified — the header is set on every response, but the real-world impact is low because no credentialed cookies are exposed cross-site.
- **Location:** `src/index.ts:40,51-52` (preflight + every real response); not set on the static-asset fast-path (`src/index.ts:88-91`) but set everywhere else.
- **Description:** Every response from the Worker, including JSON API responses, carries `Access-Control-Allow-Origin: *`. `Access-Control-Allow-Credentials` is **never** set (confirmed by grep). Browsers forbid credentialed responses when ACAO is `*`, so cross-origin `fetch(..., {credentials:'include'})` cannot read these responses.
- **Exploit/Impact:** Low. The credentialed session cookie (`avs-session`) and the `isAgeVerified` cookie cannot be exfiltrated cross-origin via this CORS header. The residual risk is that `*` allows uncredentialed cross-origin reads of `/validateVerificationPayload`, `/result/isSuccess`, `/callback`, and `/getVerificationPayloadAndUrl` *responses* — i.e. an attacker site can drive a victim's browser to call these and read the JSON, but without credentials the calls operate on attacker-supplied data, not the victim's session. Still, `*` is the wrong default for a service that has a credentialed surface.
- **Minimal fix:** Replace `*` with a partner-origin allowlist reflected dynamically (echo the request `Origin` only if it is in the allowlist). Keep `Access-Control-Allow-Credentials` unset unless a specific route needs it.

---

### [MEDIUM] 5. `isAgeVerified` cookie is non-HttpOnly and replayable
- **Status:** Verified
- **Location:** `src/routes/result.ts:160-174` (sets the cookie); `src/config.ts:47-50` (`httpOnly: false, secure: true, maxAge: 30d`).
- **Description:** On success, the encrypted `successPayload` is written to the `isAgeVerified` cookie:
  ```ts
  // src/routes/result.ts:163
  const cookieValue = `isAgeVerified=${successPayload}; Path=/; Max-Age=${config.cookie.maxAge / 1000}${config.cookie.secure ? '; Secure' : ''}${config.cookie.httpOnly ? '; HttpOnly' : ''}`;
  ```
  Because `config.cookie.httpOnly === false` (`config.ts:48`), no `HttpOnly` flag is emitted. The cookie value is the entire encrypted success proof. There is also **no `SameSite` attribute** on this cookie (unlike `avs-session` which is `SameSite=Lax` — `session.ts:159`), so it defaults to `Lax` in modern browsers but is still sent on top-level navigations from any origin.
- **Exploit/Impact:**
  - Any XSS in the page (e.g. via the loaded vendor JS, see Finding 4) can `document.cookie` read the proof-of-age token and exfiltrate it.
  - Anyone who obtains the token (XSS, log injection, shared device, MITM downgrade if HSTS absent — see Finding 4) can replay it for 30 days by setting the cookie on any request, on any browser, on any device. The token is bearer, unbound to device/IP/UA.
  - The decrypted payload also leaks internal structure (`userData`, original `userIpStr`, etc.) to whoever decrypts it (see Finding 8 for how).
- **Minimal fix:** Set `httpOnly: true` in `config.ts:48` (the cookie is consumed server-side by `/token/iframeCheck` reading it from the `Cookie` header — `token.ts:57` — so JS does not need access). Add `SameSite=Lax` (or `Strict` if the embed model permits) to the cookie string at `result.ts:163`. Reduce `maxAge` from 30 days to the shortest acceptable. Bind the proof to device/IP/UA hashes inside the encrypted payload and re-check on use.

---

### [MEDIUM] 10. Trust of `CF-Connecting-IP` / `request.cf` with insecure defaults
- **Status:** Verified
- **Location:** `src/routes/index.ts:81-87`:
  ```ts
  const userIpCountry = requestCf?.country || 'US';
  const userIpState   = requestCf?.regionCode || 'TX';
  const userIp        = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
  ```
  These flow into the encrypted payload and are later used to pick the age-of-majority threshold via `config.countryAgeMajority` (`config.ts:57-90`, surfaced to the client in `token.ts:192`).
- **Description:** `CF-Connecting-IP` is a request header. In the normal Cloudflare edge path it is set by Cloudflare and is trustworthy **only if** the Worker is never reached by a path that allows the client to set it (e.g. direct origin access, or a misconfigured proxy in front of Cloudflare). More importantly, when the header is absent the code defaults to `127.0.0.1`/`US`/`TX` rather than failing — so any flow where the header is stripped yields a US/TX-derived age of majority of 18. The country is then used to drive per-country age-of-majority logic that ranges from 15 (YE) to 21 (e.g. BH, US where some contexts want 21, SG, etc.).
- **Exploit/Impact:** Modest. An attacker who can strip or forge `CF-Connecting-IP` (only realistic outside the intended Cloudflare edge, or via a layer that forwards client-supplied headers) can pick the country used for the age-of-majority check. Combined with Finding 2 the country value is cosmetic anyway (the check is bypassed), but in a non-bypass path, defaulting to a known 18-country when data is missing silently weakens the check. Defaulting the IP to `127.0.0.1` is also misleading in any audit/logging.
- **Minimal fix:** Treat absence of `CF-Connecting-IP` / `request.cf.country` as a hard error (reject the request) rather than defaulting. Do not accept the header from any path that bypasses the Cloudflare edge. Within the edge, `request.cf` and `CF-Connecting-IP` are the right source — just don't paper over missing values.

---

### [LOW] 9. `/result/isSuccess` is a state-disclosure oracle
- **Status:** Verified
- **Location:** `src/routes/result.ts:264-284`; DO query `src/durable-objects/verification-session.ts:369-383`.
- **Description:** `/result/isSuccess` accepts `body.d` and asks the DO "is this payload hash in a SUCCESS state?". When the signed `avs-session` cookie is present it uses the cookie's `payloadHash`; otherwise it falls back to `(payload || '').substring(0, 64)` (`result.ts:274`) — so an unauthenticated caller can query the success state for **any** payload hash. The DO lookup is `SELECT 1 FROM sessions WHERE payloadHash = ? AND stateInt = ?` (SUCCESS) — it does not check that the caller owns the session.
- **Exploit/Impact:** Low. This tells an outsider whether *some* session for a given payload hash succeeded. The payload hash is the first 64 hex chars of the encrypted payload, which is sent to the client in URLs and is not secret by itself — but it lets an observer who has seen a `/token?d=...` link later learn whether that flow was completed successfully, including for flows they did not initiate. It is a minor information leak, not a correctness bypass.
- **Minimal fix:** Require the signed `avs-session` cookie (return an error if `!sessionContext`) and only allow the `payloadHash` from the cookie to be queried, never a caller-supplied substring.

---

### [LOW] 6. CSRF — refuted as a meaningful risk
- **Status:** Refuted (as a standalone concern)
- **Location:** All POST routes (`src/routes/index.ts:38,140,177`; `src/routes/result.ts:79,178,264`).
- **Description:** POST endpoints accept form/JSON with no CSRF token, and CORS is `*`. However:
  - The session cookie `avs-session` is `SameSite=Lax` (`session.ts:159`), so a cross-site form POST from another origin is **not** accompanied by the session cookie (Lax withholds cookies on cross-site POSTs). The `isAgeVerified` cookie has no SameSite attribute (defaults to Lax) — same outcome.
  - There are no auth cookies whose theft enables a privileged cross-site action.
  - The genuinely dangerous state-changing endpoints (`/result/success`) are protected *only* by the `successKey` token check — which Finding 2 shows is bypassable via a client-supplied `deviceLocationVerification`. I.e. the real vulnerability is Finding 2, not classical CSRF.
- **Why refuted:** Without credentials being sent cross-site (SameSite=Lax) and with no authenticated session to hijack, a pure CSRF does not unlock anything that Finding 1/2 don't already grant more directly. The fix for Finding 2 (always require the server-issued `successKey`) also closes any residual CSRF-ish path.
- **Note:** If you ever change the session cookie to `SameSite=None; Secure`, revisit this — it would then become exploitable.

---

## New findings (beyond candidates)

### [MEDIUM] N1. JSON-in-`<script>` embedding escapes only `<`, but is loaded alongside `text/javascript` vendor libs (defense-in-depth gap, not a direct XSS)
- **Location:** `src/templates/base.ts:17,34`; `src/templates/token-embed-check.ts:14,21`; data sources in `src/routes/token.ts:175-196` (attacker-controllable fields from `/getVerificationPayloadAndUrl`: `partnerColorConfig`, `ipCountry`, `deviceInfo`, `verificationTypeList`, `d`, `sessionId`).
- **Description:** Both HTML shells serialize `js` data with `JSON.stringify(...).replace(/</g, '\\u003c')` and embed it in `<script id="app-data" type="application/json">`. Escaping `<` is the canonical and sufficient protection against `</script>` breakout for a non-executed JSON script element, so this is **not** a direct XSS by itself. *However*, the same page loads a large vendor JS bundle (jQuery 3.5.1, face-api 1.7.12, tesseract 2.1.1, base64 — `token-index.ts:439-448`) from `/static/...` with no SRI (`integrity=`) and no CSP. If any of those is ever compromised (compromised build, supply-chain, or a path-traversal/overwrite in the assets dir), the JSON blob is the richest attacker-reachable target — it carries the full decrypted payload including the per-session `successKey`/`failKey` (`token.ts:178-182`).
- **Exploit/Impact:** A compromise of any static vendor file yields script execution in the verification page context, which can read `window` globals and the `#app-data` JSON (which contains `successKey`/`failKey`) — combining with Finding 2's pattern trivially, but also enabling silent key theft from legitimate user sessions.
- **Minimal fix:** Add Subresource Integrity (`integrity=...`) attributes to every vendor `<script>`/`<link>` in `token-index.ts`/`home.ts`, and add a strict CSP (Finding 4). Consider moving `successKey`/`failKey` out of the page entirely and into a server-validated flow (the page only needs to POST back through `/result/*`, which can re-derive them from the session).

### [LOW] N2. `payloadHash` (= first 64 chars of the encrypted payload) is the Durable Object partition key, so any payload mutation moves the session to a new DO
- **Location:** `src/routes/token.ts:104` (`payload.substring(0,64)`); `src/routes/result.ts:272-278`; `src/durable-objects/verification-session.ts:217,312,360`.
- **Description:** The DO is addressed by `idFromName(payloadHash)` where `payloadHash` is the first 64 hex characters of the encrypted payload string (i.e. the IV hex plus the first 48 hex of ciphertext). The DO is also where the per-session `successKey`/`failKey` are stored (`token.ts:148-158`). Because the hash is taken over the *encrypted* form, re-encrypting the same plaintext (which picks a fresh random IV — `encryption.ts:57`) yields a different `payloadHash`, a different DO, and an empty session store. Consequences:
  - `/result/isSuccess`'s fallback (`result.ts:274`) can only ever look up the original payload's DO; a re-encrypted copy is invisible to it (so the "Fix #3" comment at `result.ts:267` is correct in intent but the substring fallback still produces a hash that only matches the original).
  - Any code path that re-encrypts the payload before look-up will silently miss the session, producing 30010 "Session not found" rather than a security failure.
- **Exploit/Impact:** Low. This is a robustness/correctness issue, not a direct exploit. It does mean an attacker cannot trivially move a session between DOs by mutating the payload (any change relocates the session), which is mildly defensive. But it also means the `payloadHash` is not a content hash — it is a ciphertext-prefix identifier, so reasoning about it as "the same payload" is wrong.
- **Minimal fix:** Compute the hash over the *decrypted, canonicalized* payload (e.g. SHA-256 of the JSON) once at creation, and carry that hash in cleartext alongside the ciphertext. Use that as the DO key everywhere. Document that it is a ciphertext identifier today.

### [LOW] N3. `/callback` logs the full request body to console and Analytics Engine
- **Location:** `src/routes/index.ts:177-204` (`console.log('Callback received:', JSON.stringify(body))` and `env.ANALYTICS.writeDataPoint({blobs: ['callback_received', JSON.stringify(body).substring(0,256)]})`).
- **Description:** The `/callback` echo endpoint (no auth, CORS `*`) accepts any JSON or form body and writes it verbatim to Workers Logs and to an Analytics Engine dataset. There is no size cap beyond the 256-char substring for analytics, and the console.log is unbounded.
- **Exploit/Impact:** Low. An attacker can flood Workers Logs (log injection / cost / noise) and inject arbitrary 256-byte strings into the analytics dataset. The data is attacker-controlled and unvalidated, so any downstream analytics consumer must treat it as hostile (it currently isn't marked as such).
- **Minimal fix:** Rate-limit `/callback` (Finding 7), cap the logged body length, and validate/parse the expected callback schema before logging rather than logging raw.

### [LOW] N4. `parseInt` on multiple client fields accepts trailing garbage and silently coerces
- **Location:** `src/routes/result.ts:81,82,180,181,182` (`stepId`, `deviceLocationVerification`, `errorCode`); `src/routes/index.ts` (none on JSON `body`).
- **Description:** `parseInt(body.stepId || '0')` returns a number for inputs like `"3<script>"` or `"1e2"`. Today the downstream `isValidStep` check (`result.ts:95`) catches out-of-range `stepId`, but `deviceLocationVerification` and `errorCode` are used unchecked. This is the mechanism that makes Finding 2 trivial (`"1anything"` → 1).
- **Exploit/Impact:** Low (Finding 2 is the load-bearing consequence; the rest is hygiene).
- **Minimal fix:** Use strict numeric parsing (`Number.isFinite(Number(x))` and equality check) or a schema validator, and never branch security decisions on `parseInt` of untrusted strings without a follow-up equality/identity check.

---

## Notes on scope and non-findings

- The `<`-only JSON-in-script escaping (`base.ts:17`, `token-embed-check.ts:14`) is **sufficient** for a `type="application/json"` script element; `>` and `&` do not need escaping in that context and U+2028/U+2029 are safe inside a non-executed JSON element. This is not a finding.
- The signed `avs-session` cookie uses HMAC-SHA256 with a constant-time `crypto.subtle.verify` (`session.ts:36-103`); the signing is sound. The issue is not the cookie's integrity but what it authorizes (see Finding 2).
- The DO SQL uses parameterized queries throughout (`verification-session.ts` every `sql.exec` call uses `?` placeholders) — no SQL injection found.
- `renderTokenError` escapes `msg` (`token-error.ts:20,29-35`); `renderHome` escapes `nodeEnv` (`home.ts:239,250-256`) which is hardcoded to `'production'` (`routes/index.ts:25`). No reflected XSS in either error path.
