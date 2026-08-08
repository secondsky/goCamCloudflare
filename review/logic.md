# Business Logic & State Review

Target: goCamCloudflare (Cloudflare Workers age-verification app)
Scope: session lifecycle in the `VerificationSession` Durable Object + the
`/token`, `/result`, `/getVerificationPayloadAndUrl`, `/validateVerificationPayload`
routes. All findings verified against the actual code; citations are `file:line`.

## Summary (counts)

| Severity | Verified | Refuted | New |
|----------|----------|---------|-----|
| Critical | 1        | 0       | 1   |
| High     | 3        | 0       | 2   |
| Medium   | 3        | 1       | 2   |
| Low      | 2        | 0       | 1   |
| **Total**| **9**    | **1**   | **6**|

Of the 10 candidate findings, **9 are real** and **1 is refuted** (the race in
candidate #3 is mitigated by DO turn serialization). Six additional bugs were
found while reading the code. The single most important finding is
**[Critical] #1 — deviceLocationVerification bypass**, which lets any client
mark itself age-verified with no token and no completed verification.

---

## Findings (candidate findings 1-10)

### [CRITICAL] #1 — `deviceLocationVerification` body flag silently bypasses the success/fail token check
- **Status:** Verified (and inherited unchanged from `source/backend/app/route/result.ts:53,134`)
- **Location:** `src/routes/result.ts:82,133-142` (success) and `:181,233-242` (fail); constant at `:16`
- **Description:**
  ```ts
  const deviceLocationVerification = parseInt(body.deviceLocationVerification || '0');
  ...
  if (deviceLocationVerification === DEVICE_LOCATION_VERIFICATION_INTERNAL) {   // === 0
      if (!(reqSession.successKey && token === reqSession.successKey)) { ... return 30009 }
  }
  // falls through to "end session as success" regardless
  ```
  The token (`successKey` / `failKey`) is checked **only** when the client
  self-declares `deviceLocationVerification === 0`. Any client that sends
  `deviceLocationVerification=1` (or omits the cookie/session, see below)
  skips the secret check and the DO `end` action runs with
  `SESSION_STATE_SUCCESS`, minting a valid `isAgeVerified` cookie.
- **Is the non-zero branch a stronger alternative path?** No. The frontend
  sets `deviceLocationVerification = EXTERNAL (1)` only after a *separate*
  `/result/isSuccess` poll returns `isValidated: true`
  (`source/frontend/js/app/avsFactory.js/startPage/40-event.ts:65`). That
  poll is meant to confirm that the user verified on a second device. But
  nothing on the server ties the subsequent `/result/success?deviceLocationVerification=1`
  call to a previously-confirmed external verification. `isPayloadValidated`
  (`verification-session.ts:369-383`) just looks for any prior session row
  with `stateInt = SUCCESS` for that `payloadHash` — which is exactly what
  the attacker is trying to create. There is no separate
  "external-verification-confirmed" flag.
- **User-visible impact:** An attacker who obtains any legitimate `?d=`
  payload (e.g. the demo `/getVerificationPayloadAndUrl` endpoint mints one
  publicly) can POST
  `{stepId:3, deviceLocationVerification:1, idCountry:"US", idState:"TX"}`
  to `/result/success` and receive a valid 30-day `isAgeVerified` cookie.
  No selfie, no ID, no token. Age verification is fully bypassable.
- **Minimal fix:** Make the external path server-driven, not client-driven.
  Either (a) remove the `deviceLocationVerification !== 0` fall-through and
  require the token on every `/result/success|fail` call, or (b) when
  `deviceLocationVerification === EXTERNAL`, require a server-side flag
  previously set by the external verifier (e.g. a new DO column
  `externalVerifiedAt` written only by the partner callback) and reject if
  absent. Also: do not trust a client-supplied integer to pick which
  security control to enforce.

---

### [HIGH] #2 — `endSession` overwrites the user's real IP/country with `127.0.0.1` / `A1` in the partner-facing payload
- **Status:** Verified
- **Location:** `src/durable-objects/verification-session.ts:328-332`
- **Description:**
  ```ts
  const decryptedPayload = await AvsEncryption.decryptString(sessionData.payload, encryptionKey);
  decryptedPayload.userIpStr     = '127.0.0.1';
  decryptedPayload.userIpCountry = 'A1';
  decryptedPayload.userData      = sessionData.userData;
  decryptedPayload.callbackUrl   = '';
  decryptedPayload.verificationResult = { state, stateInt, sessionId, errorCode };
  return { payload: await AvsEncryption.encryptObject(decryptedPayload, encryptionKey) };
  ```
  This re-encrypted blob is what `/result/success` returns as `successPayload`
  (`result.ts:160`) and what the partner later sends to
  `/validateVerificationPayload` (`routes/index.ts:158-169`). The real
  client IP and country (collected at `routes/index.ts:81-87`, stored on the
  session at `verification-session.ts:236-238`) are *not* forwarded in the
  signed payload — they are replaced by loopback / `A1` (anonymous-proxy).
  Note the callback (`dispatchCallback`, line 484) *does* send the real IP,
  so the two channels disagree.
- **User-visible impact:** Any partner that relies on the
  `isAgeVerified`/`verificationPayload` to know *where* the user was (e.g.
  to apply country-specific age-of-majority, fraud rules, or audit logging)
  sees a bogus IP/country and may make the wrong compliance decision. `A1`
  resolves to age-of-majority 18 in the map (`config.ts:58`), so a user in a
  higher-threshold jurisdiction (e.g. `BH`=21, `MG`=21) could be held to the
  wrong threshold.
- **Minimal fix:** Forward the real values, or — if this is an intentional
  privacy measure (the comment is absent) — document it and remove the
  mismatch with the callback channel, which leaks the real IP anyway. If
  privacy is the goal, scrub the IP in the callback too.

---

### [HIGH] #5 — `dispatchCallback` swallows all errors; partner is never told a verification completed if the callback fails
- **Status:** Verified
- **Location:** `src/durable-objects/verification-session.ts:461-511` (try/catch at `:471-510`),
  invoked via `ctx.waitUntil` at `:302-306`; session written as SUCCESS at `:309-316` *before* the callback resolves.
- **Description:** The outbound POST to `sessionData.callbackUrl` is wrapped
  in `try/catch (err) { console.log('Callback dispatch error:', err); }`.
  The session row is already persisted as `SESSION_STATE_SUCCESS`/`FAILED`
  *before* `waitUntil(dispatchCallback(...))` resolves. There is:
  - no retry queue,
  - no `callbackPending` / `callbackAttempts` column,
  - no DLQ,
  - no surfacing of the failure to the user (the `/result/success` response
    already returned 200 with the success payload).
- **User-visible impact:** If the partner's callback endpoint is briefly
  down, returns 4xx/5xx, or times out (>5 s, `CALLBACK_TIMEOUT_MS` at `:43`),
  the user is told "verified", but the partner's business logic never runs
  (no account unlock, no age flag set on the partner side). The user is
  stuck: re-verifying won't help because `isPayloadStored` now returns true
  and the next `/token` returns `LINK_ALREADY_USED`. The partner's only
  recourse is `/result/isSuccess` polling — which is the very path that
  enables finding #1.
- **Minimal fix:** Persist a `callbackStatus` column (`pending|sent|failed`,
  attempts counter). On `dispatchCallback` failure, mark `failed` and
  schedule a bounded retry via `ctx.storage.setAlarm()` (DO alarms) with
  exponential backoff. Optionally add a partner-callable
  `/result/callbackStatus?sessionId=` so partners can reconcile.

---

### [HIGH] #6 — Defaults of `userIpCountry='US'`, `userIpState='TX'`, `userIp='127.0.0.1'` when `request.cf` / `CF-Connecting-IP` are absent
- **Status:** Verified
- **Location:** `src/routes/index.ts:81-87`
  ```ts
  const requestCf = request.cf as { country?: string; regionCode?: string } | undefined;
  const userIpCountry = requestCf?.country || 'US';
  const userIpState   = requestCf?.regionCode || 'TX';
  const userIp        = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
  ```
- **Description:** If a request reaches the Worker without `request.cf`
  populated, the user is silently treated as a US/Texas resident. `US` →
  age of majority 18 (`config.ts:87`). The age-of-majority check is
  client-side only (the `countryAgeMajority` map is shipped to the page at
  `token.ts:192`), so an attacker controls which threshold applies.
- **Can this happen in production?** Yes:
  1. Any request that does not traverse the Cloudflare proxy (e.g. a
     `wrangler dev` local run, a direct call to a `*.workers.dev` URL that
     for some reason lacks `cf`, or any custom-domain config that bypasses
     the CDN edge) has `request.cf === undefined`.
  2. The IP fallback also fires whenever `CF-Connecting-IP` is stripped
     (e.g. by an upstream proxy), so the recorded "user IP" is loopback.
- **User-visible impact:** Users in higher-threshold jurisdictions (e.g.
  Bahrain 21, Madagascar 21) could be held to the US-18 threshold and
  wrongly pass. Combined with finding #2 (which clobbers the IP to `A1`
  anyway), the partner cannot tell this happened.
- **Minimal fix:** When `request.cf` is absent, fail closed — reject with
  `30000 'Unable to determine country'` rather than defaulting. Same for the
  IP. If a known-internal dev path is needed, gate it behind an explicit env
  flag, not a silent default.

---

### [HIGH] #7 — `MAX_TEST_DURATION` is enforced, but the guard is nullified by finding #1, and the original-session path isn't covered
- **Status:** Verified with caveats
- **Location:** check at `src/routes/result.ts:123-130` (success) and
  `:223-230` (fail); constant at `:15` (`20 * 60 * 1000`)
- **Description:** The check is:
  ```ts
  if (reqSession.accessTime && (Date.now() - reqSession.accessTime) >= MAX_TEST_DURATION) { ... return 30008/30012 }
  ```
  Both success and fail paths check it (good). However:
  1. `accessTime` is set in the DO at `token.ts:153` (`Date.now()`), so it
     exists for every legitimate session — the `&&` guard rarely matters.
  2. **The check is bypassable via finding #1**: an attacker using
     `deviceLocationVerification=1` who never visited `/token` has no
     `reqSession`, gets `30010 'Session not found'` from `result.ts:118-120`
     — but if they *did* visit `/token` once to seed the cookie, the 20-min
     clock starts then and the expiry is enforced normally. So this finding
     is "works as intended, but only as strong as the path that reaches it."
  3. There is no server-side alarm that expires an *in-progress* session; a
     session row stays `stateInt=1 (IN_PROGRESS)` indefinitely in the SQLite
     table. Only the cookie expires (20 min, see #8). After cookie expiry
     the user can't reach `/result/*`, but the row lingers (the only
     cleanup is on `request_sessions`, not `sessions`, at
     `verification-session.ts:441-445`).
- **User-visible impact:** Stale `IN_PROGRESS` rows accumulate in the DO's
  SQLite. For a long-lived DO instance keyed by a popular `payloadHash`,
  this is unbounded growth.
- **Minimal fix:** Add a background sweep (DO alarm) that flips
  `IN_PROGRESS` rows older than `MAX_TEST_DURATION` to a terminal `EXPIRED`
  state, and prune very old rows. Independently, fix #1.

---

### [MEDIUM] #8 — `avs-session` cookie (20 min) vs `isAgeVerified` cookie (30 day) lifetime mismatch
- **Status:** Verified (mechanism real; "breaks the flow" is partial)
- **Location:** `avs-session` Max-Age=1200 (seconds, hardcoded) at
  `src/middleware/session.ts:159`; `isAgeVerified` Max-Age=`config.cookie.maxAge/1000`
  at `src/routes/result.ts:163`; `config.cookie.maxAge = 30 * 24 * 60 * 60 * 1000`
  (ms = 30 days) at `src/config.ts:50` → `Max-Age=2592000` (30 days).
- **Description:** The two cookies have unrelated lifetimes by design:
  `avs-session` only needs to span a single verification attempt; once
  `isAgeVerified` is minted, the session cookie is no longer needed.
  Scenarios:
  - **Session expires mid-verification** (user idle >20 min after loading
    `/token`): the next `/result/success` returns `30010 'Session not found'`
    (`result.ts:101-103,118-120`). The user must re-load `/token?d=...`. But
    `?d=` is only valid for 10 min (`PAYLOAD_EXPIRATION_TIME` at
    `verification-session.ts:42`, enforced at `:225-228`), and
    `isPayloadStored` will already be true, returning `LINK_ALREADY_USED`.
    So the user is locked out and must obtain a new payload from the
    partner. Annoying but safe.
  - **`isAgeVerified` survives 30 days** while the underlying session is
    long gone: `/validateVerificationPayload` doesn't consult the session
    at all (`routes/index.ts:158-173`), it only decrypts and checks
    `verificationResult.stateInt === SUCCESS`. So the 30-day cookie remains
    fully valid even if the DO row was deleted. That's the *intent* of a
    stateless signed-payload cookie, so not a bug — but it means the
    partner has no server-side way to revoke a still-valid 30-day cookie
    short of rotating `ENCRYPTION_KEY` (which invalidates everyone).
- **User-visible impact:** No correctness break, but partners cannot revoke
  a single user's "verified" status; it self-destructs only after 30 days.
- **Minimal fix:** If per-user revocation is required, add a server-side
  sessionId blocklist checked in `/validateVerificationPayload`. Otherwise
  document the 30-day irrevocability.

---

### [MEDIUM] #9 — Payload expiration (`PAYLOAD_EXPIRATION_TIME = 10 min`) is enforced, but only on the *first* `/token` visit
- **Status:** Verified
- **Location:** creation at `routes/index.ts:84` (`creationTimestamp = Date.now()`);
  enforcement at `verification-session.ts:225-228`:
  ```ts
  if (payloadParsed.creationTimestamp &&
      (payloadParsed.creationTimestamp + PAYLOAD_EXPIRATION_TIME) < Date.now()) {
      sessionState = SESSION_STATE_LINK_EXPIRED;
  }
  ```
- **Description:** The 10-min check runs inside `startSession`, which the DO
  calls exactly once per `/token` visit (and on every `/token` visit, since
  `start` is called unconditionally by `token.ts:108-117`). If the payload
  is expired, the session is created with `stateInt = LINK_EXPIRED` rather
  than rejected outright — so the page still renders, the audit log records
  `session_created {state: 'expired'}`, and `storePayload` still runs (line
  231). A subsequent `/result/success` POST for that session would succeed
  because nothing in `/result/*` checks for `LINK_EXPIRED` — the
  `reqSession.accessTime` is set, the token matches, and `end` is called
  with `SESSION_STATE_SUCCESS`, overwriting the expired state.
- **User-visible impact:** A payload older than 10 minutes that was opened
  once can still be completed if the client POSTs `/result/success` within
  the 20-min cookie window. The expiry is more of a hint than a hard gate.
- **Minimal fix:** In `endSession`, reject (or auto-expire) if the session's
  current `stateInt` is `LINK_EXPIRED` or `LINK_ALREADY_USED`. In
  `/result/success|fail`, fetch the session and reject if its state is not
  `IN_PROGRESS`.

---

### [MEDIUM] #10 — `isValidStep` only validates against a fixed enum; an invalid step is rejected, not dangerous
- **Status:** Verified (the candidate's own framing is correct — minor)
- **Location:** `verification-session.ts:24-32` (`VALID_STEPS`), `:91-93`
  (`isValidStep`); check at `result.ts:95-99` (success) and `:195-199` (fail)
- **Description:** `isValidStep` returns `VALID_STEPS.includes(step)`. The
  valid steps are 1-7 (start page, selfie intro/page, scan-id intro/page,
  credit-card intro/page). An out-of-range `stepId` → `30007/30011 'Invalid
  step id'`. No injection / state corruption. The only quirk: the check
  runs *before* the session-context check (`result.ts:95` precedes `:101`),
  so an unauthenticated attacker can probe stepIds; not a real issue.
- **User-visible impact:** None beyond the intended reject.
- **Minimal fix:** None required.

---

### [LOW] #3 — "Race in `startSession` / `updateState` (read-modify-write)" — REFUTED
- **Status:** Refuted (mitigated by DO turn model)
- **Location:** `verification-session.ts:211-276` (`startSession`),
  `:345-367` (`updateState`), `:278-343` (`endSession`)
- **Description:** The candidate worried that `isPayloadStored()` then
  `storePayload()` (lines 221, 231) and the `getById`→mutate→`exec` pattern
  in `updateState`/`endSession` are non-atomic. In a normal SQL backend
  this would be a real TOCTOU. Here it is safe because:
  1. A Durable Object executes at most one `fetch()` handler at a time
     within a single DO instance (input-gate concurrency). Two concurrent
     `start` calls for the *same* `payloadHash` are routed by
     `getDoStub(env, payloadHash)` (`middleware/session.ts:112-115`,
     `token.ts:104-105`) to the **same** DO instance, so they serialize.
  2. Within a turn, the runtime can only interleave at `await` points.
     The critical sections here have **no `await` between the read and the
     write**: in `startSession`, `isPayloadStored` (sync SQL) →
     `storePayload` (sync SQL) run back-to-back after the single
     `await decryptString` at line 215. Same for `getById`→mutate→`exec`
     in `updateState`/`endSession`. So no other turn can observe a
     half-written state.
  3. `storePayload` additionally does its own existence check (`:401-410`)
     as a belt-and-suspenders.
- **Caveat:** This safety hinges on every read-modify-write being
  `await`-free between read and write. If a future change inserts an
  `await` there, the race becomes real. Worth a code comment.
- **User-visible impact:** None today.
- **Minimal fix:** Add a one-line comment in each method noting the
  no-await-between-read-and-write invariant, and consider an explicit
  `INSERT ... ON CONFLICT DO NOTHING` for `storePayload` to make the
  atomicity local to the SQL rather than dependent on the runtime model.

---

### [LOW] #4 — Double decryption of the payload (DO + token route)
- **Status:** Verified (wasteful, not incorrect)
- **Location:** DO decrypts at `verification-session.ts:215`
  (`AvsEncryption.decryptString(payload, encryptionKey)`); token route
  decrypts again at `src/routes/token.ts:132` with the same key on the same
  ciphertext.
- **Description:** Both decrypts use the same AES-CBC key and the same
  ciphertext, so they yield the same object (`lib/encryption.ts:80-98`).
  It's redundant work (~2x AES-CBC + JSON parse per `/token` load) and a
  minor maintainability smell (two call sites that must agree on the key),
  but it cannot produce inconsistency. The CryptoKey is cached per key
  string (`encryption.ts:16-29`), so the import cost is paid once.
- **User-visible impact:** Slightly higher CPU per page load; no functional
  issue.
- **Minimal fix:** Have the DO `start` response include the parsed fields
  the template needs (`userIpCountry`, `httpParamList`, `userData.colorConfig`,
  `linkBack`) — many are already returned (`StartResult.sessionInfo` /
  `http.paramList` at `:266-275`) — and drop the second decrypt in
  `token.ts`.

---

## New findings (beyond the candidates)

### [CRITICAL] N1 — `/result/isSuccess` trusts a client-supplied `d=` payload, and `getDoStub` silently falls back to a shared "default" DO
- **Status:** New (verified)
- **Location:** `src/routes/result.ts:264-284` (handler), DO routing at
  `:277-278`; fallback at `:277`
- **Description:**
  ```ts
  const payload = body.d;
  let payloadHash: string;
  if (sessionContext) {
      payloadHash = sessionContext.payloadHash || (payload || '').substring(0, 64);
  } else {
      payloadHash = (payload || '').substring(0, 64);
  }
  const doName = payloadHash || 'default';
  const stub = getDoStub(env, doName);
  ```
  Three problems compound:
  1. **No cookie required.** An attacker with no `avs-session` cookie at all
     can POST any `d=` and learn whether *any* payload hash was ever
     validated.
  2. **The hash is `payload.substring(0, 64)`** — i.e. the first 64 chars of
     the *encrypted* payload, which for this AES-CBC format
     (`ivHex|:encryptedHex`, `encryption.ts:70`) is just the first 32 bytes
     of the random IV. So `payloadHash` is **public, random, and predictable
     per-payload only to whoever saw the URL**. But the IV is in the URL
     fragment before the `|:` — anyone who has seen the `/token?d=...` link
     knows it.
  3. **The `'default'` fallback** means an empty/missing `d` routes the
     query to a single shared DO instance named `default`. If any prior
     `start` call ever ran against `doName='default'` (which is itself
     unlikely but possible if a payload shorter than 64 chars is ever
     crafted), every caller shares state.
- **User-visible impact:** Information disclosure + amplification of #1: an
  attacker can poll `isSuccess` to detect when a victim's external
  verification landed, then immediately POST `/result/success` with
  `deviceLocationVerification=1` to mint their own cookie (see #1).
- **Minimal fix:** Require the signed `avs-session` cookie for
  `/result/isSuccess` (no anonymous polling). Reject empty `payloadHash`
  rather than routing to `'default'`. Use a cryptographic hash of the
  *ciphertext* (or a server-generated nonce stored on the session) instead
  of `substring(0,64)`.

---

### [HIGH] N2 — `linkBack` defaults to `'/'` and the token template ships it to the client; partner-controlled open redirect surface
- **Status:** New (verified)
- **Location:** `src/routes/index.ts:80` (`const linkBack = '/'`) — but the
  payload's `linkBack` field is what's actually used:
  `verification-session.ts:247` (`linkBack: payloadParsed.linkBack`),
  `:266-275` returns it; `token.ts:115-116,180` base64-encodes it into the
  page as `backLink`.
- **Description:** `linkBack` comes straight out of the encrypted payload
  with no validation. Since `/getVerificationPayloadAndUrl` is a public
  endpoint that lets the caller set *only* `callbackUrl`, `colorConfig*`,
  and `demoPageUrl` — not `linkBack` — the `linkBack='/'` is hardcoded by
  the minting route. **However**, any partner that builds its own payload
  (the spec is `ivHex|:encryptedHex`, key is shared per deployment) can set
  `linkBack: 'https://evil.com'` and it will be rendered into the page's
  back button verbatim. There is no scheme/host allowlist.
- **User-visible impact:** If `ENCRYPTION_KEY` is shared with partners (a
  common B2B pattern), a malicious partner can craft payloads that redirect
  users off-site after verification. Lower risk if the key is fully secret.
- **Minimal fix:** Validate `linkBack` in `startSession`: require same-origin
  against `payloadParsed.websiteHostname` or reject non-`/`-relative URLs.

---

### [HIGH] N3 — `startSession` overwrites a prior session's row via `INSERT OR REPLACE` keyed only on `sessionId`... but `sessionId = crypto.randomUUID()`, so prior rows are safe; the real bug is `stateInt` clobbering on `end`
- **Status:** New (verified — re-framed; the original concern dissolves but a related one remains)
- **Location:** `verification-session.ts:251-258` (insert), `:309-316` (end),
  `:357-364` (updateState)
- **Description:** Because `sessionId` is a fresh UUID each `start`,
  `INSERT OR REPLACE` never actually replaces. So that's fine. The real
  issue: `endSession` and `updateState` rewrite the **entire row** including
  `createdAt = Date.now()`, which silently *resets the row's creation
  timestamp* to the end time. Any future logic that depends on "when was
  this session started" (e.g. the missing expiry sweep from #7, or
  analytics) will see the end time as the start time. The original
  `stateInt` is also overwritten without checking that the transition is
  legal: nothing prevents `IN_PROGRESS → IN_PROGRESS` (no-op re-end), or
  re-ending an already-`SUCCESS` session, which would re-fire the partner
  callback (see #5) and re-mint a fresh 30-day cookie.
- **User-visible impact:** Repeated `/result/success` calls (e.g. double
  submit, retry) each fire another partner callback and mint another
  30-day cookie, even though the session is already terminal. Partners
  that aren't idempotent will double-process the user.
- **Minimal fix:** In `endSession`, fetch first and short-circuit if
  `stateInt` is already terminal (`SUCCESS`/`FAILED`/`EXPIRED`/`ALREADY_USED`).
  Preserve `createdAt` across updates.

---

### [MEDIUM] N4 — Session cookie's HMAC comparison is not actually constant-time despite the comment
- **Status:** New (verified)
- **Location:** `src/middleware/session.ts:59-103` (`verifySessionId`)
- **Description:** The code comment says "Timing-safe comparison" and the
  intent is to use `crypto.subtle.verify`. But the flow is:
  1. `signSessionId(sessionId)` re-signs (line 67) — irrelevant work.
  2. Compares hex-string **lengths** of the two hex signatures (line 74):
     `if (a.byteLength !== b.byteLength) return null;` — this length check
     happens *before* the constant-time verify and leaks length, but since
     HMAC-SHA256 always produces a 64-hex-char signature, this is fine in
     practice.
  3. The actual `crypto.subtle.verify` at line 95 *is* constant-time.
  So the implementation is safe, but the re-sign at line 67 and the manual
  hex byte-loop at lines 90-93 are dead/confusing code. More importantly,
  **`verifySessionId` parses the `sessionId` part out of the cookie value
  before verification** (line 62-63: `sessionId = signedValue.substring(0, dotIndex)`)
  and uses it as the message. An attacker can submit any `payloadHash` /
  `requestSessionId` they like as long as the HMAC matches — which they
  can't forge without the key. So this is fine, but the structure makes
  audit hard.
- **User-visible impact:** None functionally. Minor: each verification does
  two HMAC operations instead of one.
- **Minimal fix:** Drop the re-sign at line 67 and the hex re-encode loop;
  just `crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(sessionId))`.

---

### [MEDIUM] N5 — `getConfig` caches the config across requests including `cacheBuster: Date.now()`
- **Status:** New (verified)
- **Location:** `src/config.ts:24,27,33,53`
- **Description:** `_cachedConfig` is module-level and reused for the entire
  Worker isolate lifetime. `cacheBuster: Date.now()` (line 53) is therefore
  frozen at the isolate's first request. Every subsequent request ships the
  same `cacheBuster`, defeating its purpose as a cache-busting query string
  for static assets. More importantly, `ENCRYPTION_KEY` is captured at first
  call — if the secret is rotated, the running isolate keeps the old key
  until eviction, so decrypts of *new* payloads fail and encrypts use the
  old key (producing payloads the partner can't read with the new key).
- **User-visible impact:** Stale asset cache-busting (cosmetic); potential
  decrypt failures / key-skew after secret rotation (operational).
- **Minimal fix:** Either don't cache (recompute is cheap), or cache only
  the immutable parts and recompute `cacheBuster` per call. For key
  rotation, document that isolates must be drained.

---

### [LOW] N6 — `/getVerificationPayloadAndUrl` hardcodes `userId: 0`, `verificationTypeList: ['selfie','scanId']`, and skips `userIpState` validation
- **Status:** New (verified)
- **Location:** `src/routes/index.ts:91-122`
- **Description:** The minting route sets `userId: 0` (line 95) and a fixed
  `verificationTypeList` (line 112) regardless of partner input. This means
  the partner callback and the `isAgeVerified` cookie always claim
  `userId=0`, so the partner cannot tell *which* user verified from the
  payload alone — they must correlate via `sessionId` or the callback's
  timing. Also `showDetectedAgeNumber: true` is hardcoded (line 111),
  leaking the detected age to the UI even for partners who'd rather hide it.
- **User-visible impact:** Partners lose user identity binding in the
  payload; age is always shown.
- **Minimal fix:** Accept `userId` and `verificationTypeList` from the
  partner form (with validation), defaulting only when absent.

---

## Notes on methodology / non-issues confirmed safe

- **`AvsEncryption` AES-CBC with no authentication (no HMAC/GCM).**
  `lib/encryption.ts:55-98` uses AES-CBC without an integrity check. A
  tampered ciphertext will *usually* fail JSON.parse (line 97) and throw,
  but an attacker who can produce a controlled bit-flip in the plaintext
  (CBC bit-flipping) and still have it parse as JSON could alter fields
  like `verificationResult.stateInt`. This is below the bar of the listed
  findings because (a) the attacker would need to know the plaintext
  structure and (b) `stateInt` is checked server-side against the session
  row — but it's worth noting that the "signed payload" is not actually
  signed, only encrypted. Switching to AES-GCM (`crypto.subtle` supports
  it) would close this for free.
- **`storePayload`'s existence check + insert** is two statements but, per
  the DO turn model discussion in #3, safe in practice.
