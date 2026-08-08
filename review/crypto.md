# Cryptography & Session Integrity Review

**Target:** goCamCloudflare (Cloudflare Workers age-verification app)
**Reviewer:** Adversarial cryptography / session-integrity pass
**Date:** 2026-08-08
**Scope:** `src/lib/encryption.ts`, `src/lib/random.ts`, `src/middleware/session.ts`, `src/durable-objects/verification-session.ts`, `src/routes/{result,token,index}.ts`, `src/config.ts`, `.gitignore`, `.env.example`, frontend `avsFactory.js`

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High     | 4 |
| Medium   | 4 |
| Low      | 3 |
| **Total**| **14** |

**Most important finding:** [CRITICAL] `.dev.vars` is not gitignored AND `.env.example` ships a real, correctly-sized 32-byte AES-256 key (`zIkmW2zEgzlTLTRC5xeMbcOhHcE5sBHB`). Anyone who deployed this repo's example key as-is would be decryptable by anyone who reads the repo. Combined with the unauthenticated AES-CBC ciphertexts, this is a total break of confidentiality and integrity for every payload and cookie.

---

## Findings (candidate issues)

### [CRITICAL] #9 — `.dev.vars` is NOT gitignored; `.env.example` ships a live, correctly-sized AES-256 key

- **Status:** VERIFIED
- **Location:**
  - `.gitignore:59` (only `.env` is ignored, `.dev.vars` is absent)
  - `.env.example:5` — `ENCRYPTION_KEY="zIkmW2zEgzlTLTRC5xeMbcOhHcE5sBHB"`
  - `wrangler.jsonc` (no `.dev.vars` in ignore; Cloudflare Workers uses `.dev.vars` for local secrets)
- **Evidence collected at review time:**
  - `git check-ignore .dev.vars` → exit code 1 (NOT ignored)
  - `git ls-files .dev.vars` → empty (not currently tracked, but a local file `~81 bytes` exists at `.dev.vars` and is *not* protected from accidental commit)
  - `git log --oneline -- .env.example` → `552303a [config-feature] adding env feature` (the key is committed in the repo history)
  - The key is exactly 32 ASCII chars = 32 bytes UTF-8 = a **valid raw AES-256 key** as imported by `importKey('raw', …)` in `encryption.ts:19-26`.
- **Attack scenario:**
  1. Operator runs `wrangler deploy` and (because the docs/example suggest it) sets `ENCRYPTION_KEY` to the example value, or copies `.env.example` to `.dev.vars`.
  2. Every `?d=` payload, every `isAgeVerified` cookie, and every callback redirect URL is encrypted under a key that is **public on GitHub**.
  3. Attacker decrypts any captured `?d=` to read `callbackUrl`, `userIpStr`, `userData`; forges `?d=` payloads with arbitrary `callbackUrl`/`creationTimestamp` (bypassing the 10-minute expiry, since `creationTimestamp` is inside the unauthenticated ciphertext — see #1); forges an `isAgeVerified` cookie that decrypts to `{verificationResult:{stateInt:2,…}}` to spoof a successful age verification on `/validateVerificationPayload` (`src/routes/index.ts:156-173`).
  4. Separately, any developer who locally created `.dev.vars` can `git add .dev.vars` with no warning — the file is silently tracked.
- **Minimal fix:**
  1. Add `.dev.vars` and `.dev.vars.*` to `.gitignore`.
  2. `git filter-repo` (or BFG) to purge `.env.example` from history; replace the key with a clearly-fake placeholder like `ENCRYPTION_KEY="CHANGE_ME_32_BYTES_OF_RANDOMNESS_xx"`.
  3. Rotate any deployed key that matched the example.
  4. Add a startup check in `config.ts` that refuses to boot if `env.ENCRYPTION_KEY === 'zIkmW2zEgzlTLTRC5xeMbcOhHcE5sBHB'`.

---

### [CRITICAL] #1 — AES-CBC without authentication: ciphertexts are malleable and travel in URLs + cookies

- **Status:** VERIFIED (severity depends on key secrecy; with the leaked example key it is Critical, otherwise High)
- **Location:** `src/lib/encryption.ts:55-98` (`encryptObject`/`decryptString` use `{name:'AES-CBC'}` with no MAC, no GCM); ciphertexts flow through:
  - URL param `?d=` — `src/routes/index.ts:127`, `src/routes/token.ts:94,187`
  - `isAgeVerified` cookie — `src/routes/result.ts:163`
  - DO `payloads` table and `sessions.data` — `verification-session.ts:231,246,328`
- **Description / attack:**
  AES-CBC has no integrity tag. `crypto.subtle.decrypt` only fails on padding errors (PKCS#7), so an attacker who can modify a ciphertext can flip bits in a controlled way (CBC bit-flipping): flipping bit `i` of ciphertext block `n` flips the same bit of plaintext block `n+1` while corrupting block `n` (which the attacker can often position in a non-load-bearing field). The plaintext is JSON, so the attacker does not need to know the key — only the approximate byte offsets of the fields they want to change.
  - **`?d=` payload tampering:** The decrypted object is consumed in `token.ts:132-189` and `verification-session.ts:215-248`. Fields read after decrypt: `callbackUrl` (used as a POST target in `dispatchCallback`, `verification-session.ts:491`), `creationTimestamp` (controls the 10-minute link expiry at `verification-session.ts:225-228`), `linkBack`, `userData`, `userIpStr`, `httpParamList`. An attacker who captures a legitimate `?d=` can flip bits in the `creationTimestamp` region to extend its lifetime indefinitely, or alter `callbackUrl` to redirect the server-side callback (which posts `userData`, IP, device info) to an attacker-controlled URL.
  - **`isAgeVerified` cookie tampering:** Set at `result.ts:163` from `endResult.payload` (a re-encrypted object). Consumed at `index.ts:158` (`/validateVerificationPayload`) which reads `verificationResult.stateInt` and trusts it. An attacker who captures a *failed* verification cookie can bit-flip `stateInt` from `3` (FAILED) to `2` (SUCCESS). The only integrity check is `typeof payloadParsed.verificationResult === 'undefined'` (`index.ts:163`) — a presence check, not an authenticity check. The padding-oracle / bit-flip does not need key knowledge.
  - What *partially* stops naive tampering: JSON structure must remain valid and PKCS#7 padding must realign, so single-bit flips often break parsing. But multi-block CBC malleability (e.g., swapping/truncating trailing blocks, or targeted bit-flips in known plaintext regions like `creationTimestamp` which is a known-length number) is practical. **No MAC means there is no cryptographic barrier**, only JSON fragility.
- **Minimal fix:** Switch to AES-256-GCM (`{name:'AES-GCM', iv}`) — nearly a drop-in in Web Crypto, same `importKey`/`encrypt`/`decrypt` API but produces a 16-byte tag that `decrypt` verifies. The `ivHex|:ciphertextHex` format can stay (tag is appended to ciphertext automatically by `crypto.subtle.encrypt` for GCM). This also fixes #6-style padding-oracle classes. If GCM is impossible, add HMAC-SHA256 over `iv||ciphertext` (encrypt-then-MAC) and verify before decrypt.

---

### [CRITICAL] #3 — `payloadHash` is `payload.substring(0,64)`, not a cryptographic hash; it routes DO traffic and keys uniqueness

- **Status:** VERIFIED
- **Location:**
  - Definition: `src/durable-objects/verification-session.ts:217` — `const payloadHash = payload.substring(0, 64);`
  - DO routing: `src/routes/token.ts:104-105` (`getDoStub(env, payloadHash)`), `src/routes/result.ts:105,205,278`
  - Uniqueness key: `verification-session.ts:401-416` (`payloads.payloadHash PRIMARY KEY`)
  - "Already used" gate: `verification-session.ts:221-223` (`isPayloadStored` → `SESSION_STATE_LINK_ALREADY_USED`)
  - Identity inside the signed cookie: `src/middleware/session.ts:157` (`createSessionCookie(payloadHash, …)`)
- **Description / attack:**
  The first 64 chars of an `encryptObject` output is `ivHex` (32 bytes of IV = 64 hex chars; see `encryption.ts:67,70`). The IV is **random per encryption** (`crypto.getRandomValues`, line 57). Therefore:
  - `payloadHash` is effectively a random 64-hex-char string derived from the IV. It is **not** a content hash.
  - Two encryptions of the *same plaintext* produce two completely different `payloadHash` values (different IVs).
  - This means the `payloads` table uniqueness check (`isPayloadStored`, `verification-session.ts:418-427`) **does not deduplicate by content** — re-encrypting the same verification request creates a new payload row and a new DO instance every time. The "link already used" gate at `verification-session.ts:221-223` is bypassable simply by re-requesting `/getVerificationPayloadAndUrl` (which generates a fresh IV and thus a fresh `payloadHash`). An attacker can get unlimited fresh verification links.
  - DO routing (`idFromName(payloadHash)`) is attacker-influenced: an attacker who controls the `?d=` param controls which DO instance handles the request. Since `payloadHash = first 64 chars of ?d=`, and the IV portion is attacker-supplied via the URL, an attacker can route arbitrary requests to arbitrary DO instances (subject to the DO decrypting the payload successfully). This enables targeted load on a single DO and potentially influences cross-request state collisions if two crafted payloads share a prefix.
  - Predictability: the IV is CSPRNG-derived, so `payloadHash` is not predictable in advance — but it is **chosen by whoever builds the `?d=` URL**. The server derives no independent hash of the decrypted content.
- **Collision risk:** Negligible for accidental collisions (64 hex chars = 256 bits of IV space). The risk is *semantic*, not collision: the identifier has no binding to plaintext content.
- **Minimal fix:** Derive `payloadHash` as `SHA-256(decryptedPayload canonicalized)` *inside the DO after decrypt*, not from the ciphertext prefix. Use that content hash for `payloads` dedup and "already used" logic. For DO routing, keep using the content hash (stable per logical verification) rather than the per-encryption IV.

---

### [HIGH] #2 — Key reuse: one `ENCRYPTION_KEY` for both AES-CBC and HMAC cookie signing

- **Status:** VERIFIED (hygiene with a real, if not directly-exploitable, risk)
- **Location:**
  - HMAC key source: `src/middleware/session.ts:36-54` — `signSessionId(sessionId, key)` imports `key` as the raw HMAC key.
  - Callers pass `config.encryption.key` / `encryptionKey`: `session.ts:143` (`getSessionContextFromRequest(request, encryptionKey)`), `session.ts:155` (`createSessionCookie(…, encryptionKey)`), and transitively `result.ts:76`, `token.ts:199`.
  - AES key source: `src/lib/encryption.ts:16-29` — same string used as raw AES key.
- **Description / attack:**
  The same secret is the AES-CBC key AND the HMAC-SHA256 key. No direct cross-protocol attack is publicly known for AES-CBC + HMAC-SHA256 with the *same* key (unlike, e.g., reusing a key across AES-CBC and AES-GCM, or HMAC and CBC-MAC). The realistic severity is defense-in-depth: a future weakness in either construction, or an implementation bug that leaks one derivative, would compromise both confidentiality and authenticity. It also violates the standard cryptographic principle that a key must be dedicated to a single purpose.
- **Minimal fix:** Derive purpose-bound subkeys with HKDF:
  ```ts
  const aesKey  = await hkdf(ENCRYPTION_KEY, 'avs/aes/v1',  32);
  const hmacKey = await hkdf(ENCRYPTION_KEY, 'avs/hmac/v1', 32);
  ```
  Web Crypto exposes HKDF via `crypto.subtle.deriveBits` with `'HKDF'`. Feed `aesKey` to `importKey` for AES and `hmacKey` to the HMAC `importKey`. This is a one-line-purpose change per call site.

---

### [HIGH] #4 — Non-constant-time token comparison (`===`) on `successKey` / `failKey`

- **Status:** VERIFIED
- **Location:**
  - `src/routes/result.ts:134` — `if (!(reqSession.successKey && token === reqSession.successKey))`
  - `src/routes/result.ts:234` — `if (!(reqSession.failKey && token === reqSession.failKey))`
- **Description / attack:**
  `successKey`/`failKey` are 32-hex-char secrets (`AvsRandom.generateRandomString(32)`, `token.ts:140-141`). The check uses JS `===`, which short-circuits on the first non-matching character — a classic timing side-channel. In a Cloudflare Worker there is **no application rate limit** (the code never throttles `/result/success`), and although network jitter is significant, an attacker averaging many requests per byte position can statistically recover the token byte-by-byte. Worker CPU timing is also exposed via the `Server-Timing` header behavior and response latency.
  - Mitigating factor: the token is 32 hex chars (16 bytes of entropy) and only valid for one session for ~20 minutes (`MAX_TEST_DURATION`). A full timing recovery requires thousands of precise measurements per position within that window. Practical difficulty is high but not impossible, especially for a high-traffic deployment where the attacker can amortize across many sessions.
  - Note: the frontend (`avsFactory.js:78-80,266-268`) sends `token: successKey` (the raw key, not the base64 blob), so the value being compared is exactly the stored secret.
- **Minimal fix:** Compare in constant time:
  ```ts
  function ctEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    const enc = new TextEncoder();
    return crypto.subtle.verify('HMAC', hmacKeyZeroLen, enc.encode(a), enc.encode(b));
    // or a manual XOR-accumulate over Uint8Array
  }
  ```
  Then `if (!(reqSession.successKey && ctEqual(token, reqSession.successKey)))`.

---

### [HIGH] #8 — Session cookie integrity relies on HMAC, but the signed payload includes an attacker-influenced `payloadHash` (binds cookie to a DO the attacker can steer)

- **Status:** VERIFIED (the HMAC itself is sound; the *semantic* binding is weak)
- **Location:** `src/middleware/session.ts:152-160` (cookie creation), `:135-147` (verification on every protected request), `:120-130` (decode).
- **Cookie format (confirmed from code):**
  ```
  avs-session=<payloadHash>:<requestSessionId>.<hmacHex>; HttpOnly; SameSite=Lax; Max-Age=1200
  ```
  - `<payloadHash>:<requestSessionId>` is the message; `<hmacHex>` is HMAC-SHA256(message, ENCRYPTION_KEY) hex.
  - `decodeSessionValue` (`session.ts:120-130`) splits on `:` (the *first* colon) into `payloadHash` / `requestSessionId`.
  - **Wait — collision of separators:** `signSessionId` joins with `.` and the message itself contains `:`. `decodeSessionValue` splits on `:`. The signed message is `payloadHash + ':' + requestSessionId`. The signature covers the *whole* `payloadHash:requestSessionId` string. Format is consistent.
- **Can it be forged without the key?** No — forging requires HMAC-SHA256 under `ENCRYPTION_KEY`. Assuming key secrecy, the cookie is unforgeable. (This is the one piece of cryptography that is actually correct here.)
- **Is the signature verified on every protected request?** Yes — `getSessionContextFromRequest` (`session.ts:135-147`) is called by `result.ts:76` and verifies before any DO fetch.
- **Is `requestSessionId` validated against the DO?** Partially. `result.ts:110-112` calls `getRequestSession({sessionId: requestSessionId})` on the DO *routed by `payloadHash`*. If an attacker presents a valid cookie (key-compromised, see #9) with a crafted `payloadHash`, they route to a DO of their choosing and look up an arbitrary `requestSessionId`. Without the key, this is not exploitable.
- **The real weakness (ties to #3):** Because `payloadHash` is the attacker-controllable ciphertext prefix, the cookie's identity component is attacker-influenced. Even though it is signed, the signature only proves "the holder of the key signed this string" — it does not bind the session to a *server-derived* identity. Combined with #9 (leaked key), an attacker can mint a fully valid cookie for any DO.
- **Minimal fix:** (1) Rotate any leaked key. (2) Make `payloadHash` a server-derived content hash (see #3). (3) Consider binding `requestSessionId` to `payloadHash` inside the DO (reject mismatches).

---

### [MEDIUM] #5 — `verifySessionId` contains redundant/dead comparison code; the actual verification is sound but messy

- **Status:** VERIFIED (the dead code is real; the security is sound; the mess is a maintainability risk)
- **Location:** `src/middleware/session.ts:59-103`.
- **Trace of sign→encode→verify:**
  1. **Sign** (`session.ts:36-54`): `message = sessionId`; `signature = HMAC(key, message)`; returns `message + '.' + hex(signature)`.
  2. **Cookie build** (`session.ts:157-158`): `sessionValue = payloadHash + ':' + requestSessionId`; `signedValue = signSessionId(sessionValue, key)` → `payloadHash:requestSessionId.hmacHex`.
  3. **Verify** (`session.ts:59-103`):
     - Split on last `.` → `sessionId` (= `payloadHash:requestSessionId`), `signatureHex`.
     - **Dead block (lines 66-74):** Re-signs `sessionId`, extracts `expectedSigHex`, UTF-8-encodes both hex strings, compares `byteLength`. This is *redundant* — the result is never used except for an early-exit `return null` on length mismatch. The actual verification happens later at lines 95-100.
     - **Real verification (lines 77-100):** Re-imports the HMAC key (cached), hex-decodes the **user-supplied** `signatureHex` to bytes, and runs `crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(sessionId))`. This is constant-time and correct.
- **Is the constant-time verification sound?** Yes — `crypto.subtle.verify` for HMAC is implemented constant-time in V8/Workers. The redundant byte-length check at line 74 leaks only whether the *hex string length* matches (64 chars expected), which is not sensitive.
- **Subtle flaw?** One real issue: if `signatureHex` has odd length, the hex-decode loop at lines 90-93 silently produces a truncated `sigBytes` (`signatureHex.length / 2` truncates; the loop runs over pairs and reads `substring(i, i+2)` — an odd-length string yields a final 1-char substring that `parseInt(_,16)` parses, but `Uint8Array(length/2)` is sized to the truncated length, so the last partial byte is dropped). `crypto.subtle.verify` will then reject it. Not exploitable, but fragile.
- **Minimal fix:** Delete lines 66-87 (the dead re-sign/compare block) and rely solely on `crypto.subtle.verify`. Validate `signatureHex.length === 64 && /^[0-9a-f]+$/` before decoding.

---

### [MEDIUM] #6 — `decryptString` returns `any`; every call site trusts JSON shape with no validation

- **Status:** VERIFIED
- **Location:** `src/lib/encryption.ts:80,97` (`Promise<any>` via `JSON.parse`).
- **Call sites and fields read without validation:**
  1. `src/durable-objects/verification-session.ts:215-248` (`startSession`): reads `payloadParsed.userData`, `userIpStr`, `userIpCountry`, `userIpState`, `websiteHostname`, `verificationVersion`, `httpParamList.userAgent`, `callbackUrl`, `creationTimestamp`, `linkBack`. None type-checked. `callbackUrl` is later used directly in `fetch(sessionData.callbackUrl, …)` (line 491) — a non-string or malformed value can throw or be coerced.
  2. `src/durable-objects/verification-session.ts:328-338` (`endSession`): reads/writes `decryptedPayload.userIpStr`, `userData`, `callbackUrl`, `verificationResult`. Then **re-encrypts** the mutated object into the `isAgeVerified` cookie payload (line 341) — so any junk field survives into the cookie.
  3. `src/routes/token.ts:132-189` (`renderTokenPage`): reads `payloadParsed.userIpCountry`, `httpParamList.showDetectedAgeNumber`, `httpParamList.verificationTypeList`, `userData.colorConfig`. All unvalidated; passed into HTML template (potential XSS if `colorConfig` strings reach inline styles — out of scope but related).
  4. `src/routes/index.ts:158-173` (`/validateVerificationPayload`): reads `payloadParsed.verificationResult.stateInt` and `.sessionId`. Only check is `typeof verificationResult === 'undefined'` — no shape validation.
- **Attack scenario:** Combined with #1 (no MAC) or #9 (leaked key), an attacker can craft a ciphertext whose decrypted JSON has maliciously shaped fields (e.g., `callbackUrl` pointing to an attacker server that receives `userData`/IP; `verificationResult.stateInt = 2` to spoof success). Without #1/#9, the attacker cannot produce a valid ciphertext, so this is a *dependency amplifier*, not a standalone exploit.
- **Minimal fix:** Define a `VerificationPayload` interface (zod or hand-rolled) and validate `JSON.parse` output before any field access. Reject unknown keys.

---

### [MEDIUM] #7 — IV generation is correct, but key derivation uses the raw string as AES key bytes (fragile; no KDF)

- **Status:** PARTIALLY VERIFIED (IV is fine; key handling is a design weakness)
- **Location:** `src/lib/encryption.ts:16-29` (key import), `:57` (IV).
- **Findings:**
  - **IV (correct):** `crypto.getRandomValues(new Uint8Array(16))` at line 57 — fresh CSPRNG IV per `encryptObject` call. No deterministic IV. Good.
  - **Key derivation (weak):** `importKey('raw', encoder.encode(keyStr), …)` uses the **UTF-8 bytes of the passphrase directly as the AES key**. This requires the operator to supply *exactly* 16, 24, or 32 bytes. `.env.example` happens to ship a 32-char ASCII string (32 bytes), so it works — but:
    - An operator who sets a 16-char or 64-char passphrase gets a Web Crypto error at encrypt time (no graceful fallback).
    - There is **no KDF** (no PBKDF2/scrypt/HKDF). A low-entropy passphrase like `"password"` becomes the literal AES key with no stretching — dictionary attacks on captured ciphertexts are trivial.
    - The `keyCache` (`encryption.ts:10,17,27`) is keyed by the raw key *string*. In a Worker, this is per-isolate and the string lives in memory — acceptable for a secret in a JS runtime, but it means the raw key is retained as a JS string (not zeroizable). Standard for Workers, noted only.
  - **`keyCache` safety:** Map is module-level static. Two different keys get different `CryptoKey` objects. No cross-contamination. Safe in normal use.
- **Minimal fix:** Derive the AES key via HKDF or PBKDF2 from the passphrase so any-length secrets are acceptable and low-entropy secrets are stretched:
  ```ts
  const salt = encoder.encode('avs-aes-256-salt-v1');
  const baseKey = await crypto.subtle.importKey('raw', encoder.encode(keyStr), 'PBKDF2', false, ['deriveBits']);
  const aesBytes = await crypto.subtle.deriveBits({name:'PBKDF2', salt, iterations:100000, hash:'SHA-256'}, baseKey, 256);
  ```
  (Or, if the key is guaranteed high-entropy, just enforce a length check and document that it must be 32 random bytes.)

---

### [LOW] #10 — `base64EncodeObject`/`base64DecodeString` use `btoa`/`atob`, which throw on non-Latin1

- **Status:** VERIFIED (low real-world impact for current data; latent bug)
- **Location:** `src/lib/encryption.ts:103-112`.
- **Data flowing through these helpers:** `token.ts:178-182` encodes `{successKey, failKey, backLink}`.
  - `successKey`/`failKey`: 32 hex chars (`AvsRandom.generateRandomString(32)` produces `[0-9a-f]` — see `random.ts:8-13`). Pure ASCII. Safe.
  - `backLink`: comes from `payloadParsed.linkBack` (`token.ts:181`), set at `index.ts:80` to `'/'` (safe) — but the decryption at `token.ts:132` trusts the ciphertext, so an attacker-controlled `linkBack` (under #1/#9) could contain UTF-8. `btoa(JSON.stringify({backLink:'ü'}))` throws `InvalidCharacterError`. The route would 500 instead of gracefully rejecting.
- **Frontend decode:** `avsFactory.js:78,266` calls `Avs.Helper.Common.decodeBase64(token)` (uses `js-base64`, which handles UTF-8). Asymmetry: server uses `btoa` (Latin1-only), frontend uses a UTF-8-safe lib. Any non-Latin1 char in `backLink` corrupts round-trip.
- **Minimal fix:** Use a UTF-8-safe base64:
  ```ts
  static base64EncodeObject(o: object): string {
    return btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(o))));
  }
  static base64DecodeString(s: string): any {
    const bin = atob(s);
    const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  }
  ```

---

## New findings (beyond candidates)

### [HIGH] N1 — Token gate (`deviceLocationVerification === INTERNAL`) is bypassable because the field is attacker-controlled in the POST body

- **Status:** VERIFIED
- **Location:** `src/routes/result.ts:82` (`deviceLocationVerification = parseInt(body.deviceLocationVerification || '0')`), `:133` (`if (deviceLocationVerification === DEVICE_LOCATION_VERIFICATION_INTERNAL)`), `:233` (same for fail). `DEVICE_LOCATION_VERIFICATION_INTERNAL = 0` (`result.ts:16`).
- **Description / attack:**
  The `successKey`/`failKey` token check at `result.ts:134,234` is **gated on `deviceLocationVerification === 0`**. But `deviceLocationVerification` comes from the request body (`body.deviceLocationVerification`), parsed at `result.ts:82`. An attacker who posts `{deviceLocationVerification: 1, …}` to `/result/success` skips the token check entirely and forces a session to SUCCESS without knowing `successKey`.
  - The frontend (`avsFactory.js:270`) normally sends `deviceLocationVerification: ResultPageSuccess.instance.entity.VerificationStepGlobal.deviceLocationVerification`, which defaults to `EXTERNAL (1)` for most flows and `INTERNAL (0)` only for specific internal liveness flows.
  - The server trusts the body value unconditionally. There is no server-side assertion that the session's configured verification mode matches the posted value.
  - Impact: an attacker who has a valid session cookie (obtainable by simply visiting `/token?d=…` once) can POST to `/result/success` with `deviceLocationVerification=1`, any `stepId` in `VALID_STEPS`, and **no token**, and the server will mark the session SUCCESS, dispatch the merchant callback as success, and set the `isAgeVerified` cookie. This is a **direct age-verification bypass** that does not require any cryptographic flaw.
- **Minimal fix:** Do not gate the token check on a client-supplied field. Either always require the token, or source `deviceLocationVerification` from the server-side session record (stored at `startSession` time from the payload), not from the POST body.

---

### [MEDIUM] N2 — `isAgeVerified` cookie is set without `HttpOnly` and is consumed as a bearer token by `/validateVerificationPayload`

- **Status:** VERIFIED
- **Location:** `src/config.ts:48` (`httpOnly: false`), `src/routes/result.ts:163` (cookie built without HttpOnly), `src/routes/token.ts:57-59` (`iframeCheck` reads `isAgeVerified` from `document.cookie` and ships it in HTML), `src/routes/index.ts:156-173` (`/validateVerificationPayload` decrypts and trusts it).
- **Description / attack:**
  The `isAgeVerified` cookie is `Secure; SameSite` default but **not HttpOnly**, so any page JavaScript (including third-party scripts or XSS) can exfiltrate it via `document.cookie`. Although the cookie is encrypted (AES-CBC), it functions as a bearer credential: presenting it to `/validateVerificationPayload` returns the `sessionId` of a successful verification. Combined with #1 (no MAC / malleable) and #9 (leaked key), the cookie is both readable and forgeable.
  - Even without crypto flaws: an XSS on the merchant site that embeds this iframe can steal a victim's `isAgeVerified` cookie and replay it to assert the victim's verification. The lack of `HttpOnly` is the enabling condition.
- **Minimal fix:** Set `HttpOnly` on `isAgeVerified` (the legitimate consumer is the server-side `/validateVerificationPayload`, not client JS — the `iframeCheck` flow can be reworked to read the cookie server-side via a fetch to a protected endpoint). At minimum, bind the cookie to the originating `payloadHash`/session and validate that binding server-side.

---

### [MEDIUM] N3 — `getSessionContextFromRequest` failure on `/result/isSuccess` falls back to an attacker-controllable `payloadHash`

- **Status:** VERIFIED
- **Location:** `src/routes/result.ts:264-283` (`/result/isSuccess`).
- **Description:**
  ```ts
  if (sessionContext) {
    payloadHash = sessionContext.payloadHash || (payload || '').substring(0, 64);
  } else {
    payloadHash = (payload || '').substring(0, 64);   // attacker-controlled
  }
  const doName = payloadHash || 'default';
  const stub = getDoStub(env, doName);
  ```
  If the attacker has no valid session cookie (the `else` branch), the DO routing and the `payloadHash` sent to `isPayloadValidated` both come from the request body `body.d` — fully attacker-controlled. An attacker can probe arbitrary `payloadHash` values to discover which payloads have been validated, and can route the lookup to any DO instance. Combined with #3, this means the "is this payload validated?" oracle is open to enumeration.
- **Minimal fix:** Require a valid session cookie for `/result/isSuccess` (return 30010 if `!sessionContext`), and use `sessionContext.payloadHash` exclusively — never a client-supplied `body.d` prefix.

---

### [LOW] N4 — `/result/isSuccess` uses `'default'` as a DO name fallback, creating a shared global DO instance

- **Status:** VERIFIED
- **Location:** `src/routes/result.ts:277` — `const doName = payloadHash || 'default';`.
- **Description:** When `payloadHash` is empty (empty `body.d` and no session), all such requests collapse onto a single DO named `'default'`. That DO will still execute `isPayloadValidated('')` (returns false), but the routing concentration is a (minor) DoS amplification target and a surprise hot spot.
- **Minimal fix:** Reject empty `payloadHash` with a 400 before routing.

---

### [LOW] N5 — `generateRandomString(32)` produces 32 hex chars = 16 bytes of entropy, not 32 bytes

- **Status:** VERIFIED (note, not a vuln by itself)
- **Location:** `src/lib/random.ts:7-13`, consumed at `src/routes/token.ts:140-141`.
- **Description:** `generateRandomString(32)` reads `ceil(32/2)=16` random bytes and slices to 32 hex chars. So `successKey`/`failKey` carry **128 bits** of entropy, not 256. 128 bits is still brute-force-infeasible, but the naming implies 32 chars = 32 bytes of entropy, which is misleading for any future caller who passes a larger `length` expecting proportional entropy. The hex alphabet also halves density vs. base64url.
- **Minimal fix:** Document the entropy (`length/2` bytes), or switch to base64url of `length` random bytes for full density.

---

### [LOW] N6 — `parseCookies` does not URL-decode values and splits naively, mishandling `=`/`;` in values

- **Status:** VERIFIED (low; the signed cookie values here are hex/base64 so unlikely to contain `=` or `;`, but `isAgeVerified` ciphertext is hex and safe)
- **Location:** `src/middleware/session.ts:21-31`.
- **Description:** `pair.trim().split('=')` then `rest.join('=')` handles `=` in values, but never `decodeURIComponent`s. Cookie values containing `%3B` or raw `;` are not handled per RFC 6265. Not currently exploitable given the value alphabets in use, but fragile.
- **Minimal fix:** Use the standard `cookie` package or a RFC-correct parser.

---

## Notes on what is done correctly

- `crypto.subtle.verify('HMAC', …)` in `verifySessionId` is constant-time and is the real gate for cookie authenticity (`session.ts:95-100`). The HMAC construction itself is sound assuming key secrecy.
- IVs are fresh per encryption via `crypto.getRandomValues` (`encryption.ts:57`).
- The `avs-session` cookie is `HttpOnly; SameSite=Lax; Max-Age=1200` (`session.ts:159`) — good defaults.
- `getRequestSession` data (including `successKey`/`failKey`) lives in the DO, not in the cookie — so the cookie alone does not leak the tokens.
- Durable Object storage uses parameterized SQL (`?` placeholders) throughout `verification-session.ts` — no SQL injection in the reviewed queries.

The single biggest problem is that **none of the cryptographic correctness matters if the key is public** (#9), and **even with a secret key, AES-CBC without a MAC leaves every ciphertext malleable** (#1). The token-gate bypass (N1) is an independent, non-cryptographic logic flaw that allows a complete age-verification bypass with nothing more than a valid session cookie.
