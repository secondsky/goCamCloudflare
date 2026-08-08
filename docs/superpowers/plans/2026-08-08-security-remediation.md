# Security & Quality Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remediate all Critical/High/Medium/Low issues found in the adversarial review of goCamCloudflare — an age-verification Cloudflare Worker — with a test harness covering each fix.

**Architecture:** Pure-logic modules (encryption, session, URL validation, result-gate) get unit-tested with Vitest. Stateful routes/DO get integration tests via `@cloudflare/vitest-pool-workers`. Crypto migrates AES-CBC→AES-GCM with HKDF-derived separate keys (hard cutover — old short-lived payloads/cookies age out). The verification-bypass gate is removed so the token check always runs. SSRF, PII logging, security headers, typing, DRY, and docs are all addressed in dependency order.

**Tech Stack:** Cloudflare Workers, `cloudflare:workers` DurableObject (SQLite), Web Crypto API, Vitest + `@cloudflare/vitest-pool-workers`, TypeScript (strict).

## Global Constraints

- **Test framework:** Vitest with `@cloudflare/vitest-pool-workers` (in-repo Workers testing). Pure-logic unit tests run in the default node pool; DO/route integration tests use the workers pool. Every task ships its own tests and must pass `npx vitest run` before commit.
- **Crypto cutover:** Hard cutover to AES-GCM. No CBC fallback. All existing payloads/cookies/sessions are short-lived and age out naturally. The `ENCRYPTION_ALGORITHM` env var becomes unused (kept for backwards-compatible env compatibility but ignored).
- **Key length:** `ENCRYPTION_KEY` must be exactly 32 bytes of UTF-8 (32 ASCII chars). A boot-time check in `config.ts` enforces this.
- **No new runtime dependencies** except `vitest` and `@cloudflare/vitest-pool-workers` (devDependencies). All crypto uses Web Crypto API. All URL/hex parsing is hand-rolled or built-in.
- **TDD:** Each task writes the failing test first, then the implementation.
- **Commit cadence:** One commit per task (or per sub-step within a task). Conventional commit messages.
- **Branch:** Work on a feature branch `fix/security-remediation`, not `main`.

## File Structure (files created/modified across all tasks)

**New files:**
- `vitest.config.ts` — Vitest config with two pools (default node + workers pool)
- `src/lib/url.ts` — `isSafeCallbackUrl()` SSRF validator
- `src/lib/crypto-utils.ts` — `constantTimeEqual()` and `hkdfDerive()`
- `src/lib/do.ts` — shared `callDoJson<T>()` helper (extracted from duplicates)
- `src/lib/types.ts` — `DecryptedPayload`, `VerificationResult`, type guards
- `src/lib/parse.ts` — `safeParseInt()` with NaN guard
- `test/lib/encryption.test.ts`, `test/lib/url.test.ts`, `test/lib/crypto-utils.test.ts`
- `test/lib/parse.test.ts`, `test/lib/types.test.ts`, `test/lib/do.test.ts`
- `test/routes/result.test.ts`, `test/routes/index.test.ts`
- `test/middleware/session.test.ts`
- `test/integration/worker.test.ts` — workers-pool integration tests

**Modified files:**
- `package.json` — add test script, devDependencies
- `src/routes/result.ts` — remove bypass, use shared helper, safe parse, constant-time compare
- `src/routes/index.ts` — SSRF validation, PII logging fix, fail-closed defaults, body-parse
- `src/routes/token.ts` — use shared `callDoJson`, payloadHash
- `src/lib/encryption.ts` — AES-GCM, `decryptString` typed return, `computePayloadHash`
- `src/middleware/session.ts` — HKDF HMAC key, remove dead code
- `src/durable-objects/verification-session.ts` — generic error, stop IP scrub, callback retry, terminal-state guard
- `src/index.ts` — security headers, CORS allowlist, rate limiting
- `src/config.ts` — key validation, HKDF keys, cookie config, dedup maxDuration
- `src/lib/response.ts` — no mutation
- `src/templates/base.ts`, `src/templates/token-error.ts`, `src/templates/home.ts`, `src/templates/token-embed-check.ts` — escaping
- `.gitignore`, `.env.example`, `wrangler.jsonc`, `README.md`

---

## Task 1: Test harness setup (Vitest + @cloudflare/vitest-pool-workers)

**Files:**
- Create: `vitest.config.ts`
- Create: `test/setup/sanity.test.ts`
- Modify: `package.json` (devDependencies + scripts)

**Interfaces:**
- Produces: `npx vitest run` exits 0; `npx vitest run:workers` exits 0. All later tasks add `*.test.ts` files.

- [ ] **Step 1: Install devDependencies**

Run:
```bash
npm install --save-dev vitest @cloudflare/vitest-pool-workers
```

- [ ] **Step 2: Write `vitest.config.ts`**

Create `vitest.config.ts`:
```ts
import { defineWorkersProject } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersProject({
	test: {
		// Unit tests for pure-logic modules run in the default node pool.
		// Integration tests (DO, fetch handler) use the workers pool via
		// the `test:workers` script which sets --pool=workers.
		pool: 'forks',
		include: ['test/**/*.test.ts'],
	},
});
```

- [ ] **Step 3: Add scripts to `package.json`**

Add to the `"scripts"` block in `package.json`:
```json
"test": "vitest run",
"test:workers": "vitest run --pool=workers",
"test:watch": "vitest"
```

- [ ] **Step 4: Write a sanity test**

Create `test/setup/sanity.test.ts`:
```ts
import { describe, it, expect } from 'vitest';

describe('sanity', () => {
	it('runs vitest', () => {
		expect(1 + 1).toBe(2);
	});
});
```

- [ ] **Step 5: Run tests**

Run: `npx vitest run`
Expected: 1 test passes.

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json vitest.config.ts test/setup/sanity.test.ts
git commit -m "test: add vitest harness with workers pool support"
```

---

## Task 2: Fix verification bypass — always require token (Critical #1)

**Files:**
- Create: `test/routes/result.test.ts`
- Modify: `src/routes/result.ts:132-142` (success) and `:232-242` (fail)

**Interfaces:**
- Consumes: existing `callDoJson`, `getDoStub`, `getSessionContextFromRequest`
- Produces: `/result/success` and `/result/fail` now ALWAYS check `token === reqSession.successKey` / `failKey` regardless of `deviceLocationVerification`. The `deviceLocationVerification` field is no longer read from the body for gating.

- [ ] **Step 1: Write the failing test**

This is a logic test of the gate behavior. Since the route handler depends on DO + cookie, we test the *gate function* we're about to extract.

Create `test/routes/result.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { tokenIsValid } from '../../src/routes/result';

describe('tokenIsValid', () => {
	it('returns true when token matches the stored key', () => {
		expect(tokenIsValid('abc123', 'abc123')).toBe(true);
	});

	it('returns false when token does not match', () => {
		expect(tokenIsValid('abc123', 'wrong')).toBe(false);
	});

	it('returns false when stored key is undefined', () => {
		expect(tokenIsValid('abc123', undefined)).toBe(false);
	});

	it('returns false when token is empty', () => {
		expect(tokenIsValid('', 'abc123')).toBe(false);
	});
});
```

- [ ] **Step 2: Run test — verify it fails**

Run: `npx vitest run test/routes/result.test.ts`
Expected: FAIL — `tokenIsValid` is not exported (doesn't exist yet).

- [ ] **Step 3: Extract `tokenIsValid` and remove the bypass gate**

In `src/routes/result.ts`:

Add this exported helper near the top (after the constants, before `callDoJson`):
```ts
/**
 * Check that a client-supplied token matches the server-stored key.
 * Exported for unit testing. (Constant-time comparison is added in Task 14.)
 */
export function tokenIsValid(token: unknown, storedKey: string | undefined): boolean {
	return typeof storedKey === 'string' && typeof token === 'string' && token === storedKey;
}
```

Then replace the gated block in `/result/success` (current lines 132-142):
```ts
		// Verify token (always required — no bypass via deviceLocationVerification)
		if (!tokenIsValid(token, reqSession.successKey)) {
			sessionResult.errorCode = 30009;
			await callDoJson<{ success: boolean }>(stub, 'updateState', {
				sessionId: reqSession.sessionStartId,
				stateData: sessionResult,
			});
			return Response.json(AvsResponse.errorResponse(30009, 'Invalid token'));
		}
```

Do the same replacement in `/result/fail` (current lines 232-242):
```ts
		// Verify token (always required — no bypass via deviceLocationVerification)
		if (!tokenIsValid(token, reqSession.failKey)) {
			sessionResult.errorCode = 30013;
			await callDoJson<{ success: boolean }>(stub, 'updateState', {
				sessionId: reqSession.sessionStartId,
				stateData: sessionResult,
			});
			return Response.json(AvsResponse.errorResponse(30013, 'Invalid token'));
		}
```

Remove the now-unused `deviceLocationVerification` variable declarations (lines 82 and 181) and the constant `DEVICE_LOCATION_VERIFICATION_INTERNAL` (line 16).

- [ ] **Step 4: Run test — verify it passes**

Run: `npx vitest run test/routes/result.test.ts`
Expected: 4 tests pass.

- [ ] **Step 5: Run typecheck**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/routes/result.ts test/routes/result.test.ts
git commit -m "fix(critical): always require successKey/failKey token in /result/{success,fail}

Remove the deviceLocationVerification gate that allowed skipping the
token check by sending a non-zero value. This closes the verification
bypass where any holder of a session cookie could mark themselves
age-verified without completing any selfie/ID/liveness check."
```

---

## Task 3: SSRF — validate callbackUrl (Critical #2)

**Files:**
- Create: `src/lib/url.ts`
- Create: `test/lib/url.test.ts`
- Modify: `src/routes/index.ts:60-67`

**Interfaces:**
- Produces: `isSafeCallbackUrl(urlStr: string): { ok: true } | { ok: false; reason: string }`

- [ ] **Step 1: Write the failing test**

Create `test/lib/url.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { isSafeCallbackUrl } from '../../src/lib/url';

describe('isSafeCallbackUrl', () => {
	it('accepts a valid https URL', () => {
		expect(isSafeCallbackUrl('https://partner.example.com/callback')).toEqual({ ok: true });
	});

	it('accepts a valid http URL', () => {
		expect(isSafeCallbackUrl('http://partner.example.com/callback')).toEqual({ ok: true });
	});

	it('rejects non-http(s) schemes', () => {
		expect(isSafeCallbackUrl('file:///etc/passwd').ok).toBe(false);
		expect(isSafeCallbackUrl('ftp://example.com').ok).toBe(false);
		expect(isSafeCallbackUrl('javascript:alert(1)').ok).toBe(false);
	});

	it('rejects cloud metadata IP', () => {
		expect(isSafeCallbackUrl('http://169.254.169.254/latest/meta-data').ok).toBe(false);
	});

	it('rejects loopback', () => {
		expect(isSafeCallbackUrl('http://127.0.0.1/admin').ok).toBe(false);
		expect(isSafeCallbackUrl('http://localhost/admin').ok).toBe(false);
	});

	it('rejects private ranges', () => {
		expect(isSafeCallbackUrl('http://10.0.0.1/internal').ok).toBe(false);
		expect(isSafeCallbackUrl('http://192.168.1.1/router').ok).toBe(false);
		expect(isSafeCallbackUrl('http://172.16.0.1/x').ok).toBe(false);
	});

	it('rejects IPv6 loopback', () => {
		expect(isSafeCallbackUrl('http://[::1]/x').ok).toBe(false);
	});

	it('rejects malformed URLs', () => {
		expect(isSafeCallbackUrl('not-a-url').ok).toBe(false);
		expect(isSafeCallbackUrl('').ok).toBe(false);
	});
});
```

- [ ] **Step 2: Run test — verify it fails**

Run: `npx vitest run test/lib/url.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/lib/url.ts`**

```ts
/**
 * Validate that a callback URL is safe to fetch server-side.
 * Prevents SSRF by enforcing http(s) scheme and blocking private/loopback IPs.
 *
 * Note: this validates the hostname as written. For hostnames that resolve
 * dynamically, a DNS-rebinding attack is still theoretically possible.
 * A production deployment should pair this with a partner-host allowlist.
 */

const PRIVATE_IPV4_PATTERNS: RegExp[] = [
	/^10\./,                          // 10.0.0.0/8
	/^127\./,                         // 127.0.0.0/8
	/^169\.254\./,                    // 169.254.0.0/16 (link-local + cloud metadata)
	/^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
	/^192\.168\./,                    // 192.168.0.0/16
	/^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./, // 100.64.0.0/10 (CGNAT)
];

export type CallbackUrlResult = { ok: true } | { ok: false; reason: string };

export function isSafeCallbackUrl(urlStr: string): CallbackUrlResult {
	if (!urlStr || typeof urlStr !== 'string') {
		return { ok: false, reason: 'empty' };
	}

	let parsed: URL;
	try {
		parsed = new URL(urlStr);
	} catch {
		return { ok: false, reason: 'malformed' };
	}

	if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
		return { ok: false, reason: 'bad_scheme' };
	}

	const hostname = parsed.hostname.toLowerCase();

	// Reject localhost by name
	if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
		return { ok: false, reason: 'loopback' };
	}

	// IPv4 literal checks
	for (const pattern of PRIVATE_IPV4_PATTERNS) {
		if (pattern.test(hostname)) {
			return { ok: false, reason: 'private_range' };
		}
	}

	// IPv6 loopback / link-local / unique-local
	if (hostname === '[::1]' || hostname === '[0:0:0:0:0:0:0:1]') {
		return { ok: false, reason: 'loopback' };
	}
	if (hostname.startsWith('[fc') || hostname.startsWith('[fd') || hostname.startsWith('[fe80')) {
		return { ok: false, reason: 'private_range' };
	}

	return { ok: true };
}
```

- [ ] **Step 4: Run test — verify it passes**

Run: `npx vitest run test/lib/url.test.ts`
Expected: all pass.

- [ ] **Step 5: Wire into `src/routes/index.ts`**

In `src/routes/index.ts`, add import at top:
```ts
import { isSafeCallbackUrl } from '../lib/url';
```

Replace the callback URL validation block (current lines 60-67):
```ts
		if (typeof callbackUrl !== 'string' || callbackUrl.trim() === '') {
			return Response.json(AvsResponse.errorResponse(30000, 'Invalid payload config'));
		}
		const urlCheck = isSafeCallbackUrl(callbackUrl);
		if (!urlCheck.ok) {
			return Response.json(AvsResponse.errorResponse(30000, `Invalid callback URL: ${urlCheck.reason}`));
		}
```

- [ ] **Step 6: Typecheck + full test run**

Run: `npx tsc --noEmit && npx vitest run`
Expected: no errors, all tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/lib/url.ts test/lib/url.test.ts src/routes/index.ts
git commit -m "fix(critical): validate callbackUrl to prevent SSRF

Reject non-http(s) schemes, loopback, private IP ranges, and cloud
metadata endpoints before storing the callbackUrl in the encrypted
payload. The DO later fetches this URL server-side."
```

---

## Task 4: Stop key leak — gitignore `.dev.vars`, placeholder key, boot check (Critical #3)

**Files:**
- Modify: `.gitignore`
- Modify: `.env.example`
- Modify: `src/config.ts:29-31`
- Create: `test/config.test.ts`

**Interfaces:**
- Produces: `getConfig` throws if key is missing OR is the known-leaked example key OR is not 32 bytes.

- [ ] **Step 1: Write the failing test**

Create `test/config.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { getConfig } from '../src/config';

// Reset module cache between tests — config caches itself.
beforeEach module reset is handled by importing fresh each time via vi.resetModules.

describe('getConfig validation', () => {
	it('throws when ENCRYPTION_KEY is missing', () => {
		expect(() => getConfig({ ENCRYPTION_KEY: '' } as any)).toThrow(/ENCRYPTION_KEY/);
	});

	it('throws when key is the known leaked example key', () => {
		expect(() => getConfig({ ENCRYPTION_KEY: 'zIkmW2zEgzlTLTRC5xeMbcOhHcE5sBHB' } as any)).toThrow();
	});

	it('throws when key is not 32 bytes', () => {
		expect(() => getConfig({ ENCRYPTION_KEY: 'short' } as any)).toThrow();
	});

	it('succeeds with a valid 32-byte key', () => {
		const cfg = getConfig({ ENCRYPTION_KEY: 'a'.repeat(32) } as any);
		expect(cfg.encryption.key).toBe('a'.repeat(32));
	});
});
```

Note: because `getConfig` caches at module scope, the test must use `vi.resetModules()` between cases. Replace the `beforeEach` comment with:
```ts
import { beforeEach, vi } from 'vitest';

beforeEach(async () => {
	vi.resetModules();
});
```
And each `getConfig` call must dynamically import: `const { getConfig } = await import('../src/config');`

- [ ] **Step 2: Run test — verify it fails**

Run: `npx vitest run test/config.test.ts`
Expected: FAIL (no length check, no leaked-key check).

- [ ] **Step 3: Add validation to `src/config.ts`**

Replace the key-existence check in `getConfig` (lines 29-31):
```ts
	const LEAKED_EXAMPLE_KEY = 'zIkmW2zEgzlTLTRC5xeMbcOhHcE5sBHB';

	if (!env.ENCRYPTION_KEY) {
		throw new Error('ENCRYPTION_KEY is not set. Set it via wrangler secret put or .dev.vars');
	}

	// Enforce AES-256 key length (32 bytes UTF-8)
	const keyBytes = new TextEncoder().encode(env.ENCRYPTION_KEY);
	if (keyBytes.byteLength !== 32) {
		throw new Error(
			`ENCRYPTION_KEY must be exactly 32 bytes (got ${keyBytes.byteLength}). Generate one with: openssl rand -hex 16 | xxd -r -p | base64`
		);
	}

	if (env.ENCRYPTION_KEY === LEAKED_EXAMPLE_KEY) {
		throw new Error(
			'ENCRYPTION_KEY matches the known leaked example key. Generate a new one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'latin1\'))"'
		);
	}
```

- [ ] **Step 4: Add `.dev.vars*` to `.gitignore`**

Append to `.gitignore`:
```
# Cloudflare Workers local secrets
.dev.vars
.dev.vars.*
```

- [ ] **Step 5: Replace the key in `.env.example`**

In `.env.example`, change line 5 to a clearly-fake placeholder:
```
ENCRYPTION_KEY="CHANGE_ME_GENERATE_32_RANDOM_BYTES"
```

- [ ] **Step 6: Run test — verify it passes**

Run: `npx vitest run test/config.test.ts`
Expected: all 4 pass.

- [ ] **Step 7: Commit**

```bash
git add .gitignore .env.example src/config.ts test/config.test.ts
git commit -m "fix(critical): stop encryption key leak

- Add .dev.vars to .gitignore (was only .env)
- Replace real key in .env.example with placeholder
- Boot-time validation: reject missing, wrong-length, or known-leaked keys"
```

---

## Task 5: PII logging — strip callback body from logs + Analytics (Critical #4)

**Files:**
- Modify: `src/routes/index.ts:177-204` (`/callback`)
- Modify: `src/durable-objects/verification-session.ts:509` (`dispatchCallback` error log)

- [ ] **Step 1: Modify `/callback` handler in `src/routes/index.ts`**

Replace lines 189-201 with:
```ts
		// Log only non-identifying metadata. Never log the raw body
		// (it contains user IP, userData, device info — PII).
		const callbackState = typeof body.stateInt !== 'undefined' ? String(body.stateInt) : 'unknown';
		const sessionId = typeof body.sessionId === 'string' ? body.sessionId : '';

		console.log('Callback received', { stateInt: callbackState, sessionId });

		// Write only non-identifying fields to Analytics Engine
		try {
			env.ANALYTICS.writeDataPoint({
				blobs: ['callback_received', callbackState, sessionId],
				doubles: [Date.now()],
				indexes: ['callback'],
			});
		} catch {
			// Analytics Engine may not be available in dev
		}
```

- [ ] **Step 2: Fix `dispatchCallback` error log in DO**

In `src/durable-objects/verification-session.ts` line 509, replace:
```ts
			console.log('Callback dispatch error:', err);
```
with:
```ts
			console.log('Callback dispatch error', { sessionId });
```
(The `sessionId` parameter is already in scope as a method parameter.)

- [ ] **Step 3: Typecheck**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add src/routes/index.ts src/durable-objects/verification-session.ts
git commit -m "fix(critical): stop logging PII to console and Analytics Engine

/callback was logging the full request body (user IP, userData, device
info) to both Workers Logs and the Analytics Engine dataset. Now logs
only stateInt and sessionId. The DO callback dispatch error log no
longer includes the raw error (which could contain the callback URL)."
```

---

## Task 6: DO error — return generic message, not `String(err)` (Critical quality)

**Files:**
- Modify: `src/durable-objects/verification-session.ts:203-206`

- [ ] **Step 1: Replace the DO catch block**

In `src/durable-objects/verification-session.ts`, replace lines 203-206:
```ts
		} catch (err) {
			console.error('DO error:', err);
			return Response.json({ error: String(err) }, { status: 500 });
		}
```
with:
```ts
		} catch (err) {
			console.error('DO error:', err);
			return Response.json({ error: 'internal_error' }, { status: 500 });
		}
```

- [ ] **Step 2: Typecheck**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/durable-objects/verification-session.ts
git commit -m "fix: DO 500 responses no longer leak internal error details

String(err) could surface SQLite error text, schema names, or internal
identifiers to the client. Now returns a generic 'internal_error' message."
```

---

## Task 7: AES-CBC → AES-GCM (High #5)

**Files:**
- Create: `test/lib/encryption.test.ts`
- Modify: `src/lib/encryption.ts`

**Interfaces:**
- Produces: `encryptObject`/`decryptString` now use AES-GCM. Format unchanged externally (`ivHex|:encryptedHex` where the GCM tag is appended to ciphertext automatically by Web Crypto).

- [ ] **Step 1: Write the failing test**

Create `test/lib/encryption.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { AvsEncryption } from '../../src/lib/encryption';

const TEST_KEY = 'a'.repeat(32); // 32 bytes

describe('AvsEncryption AES-GCM', () => {
	it('encrypts and decrypts an object round-trip', async () => {
		const obj = { foo: 'bar', num: 42, nested: { a: true } };
		const encrypted = await AvsEncryption.encryptObject(obj, TEST_KEY);
		const decrypted = await AvsEncryption.decryptString(encrypted, TEST_KEY);
		expect(decrypted).toEqual(obj);
	});

	it('produces a different ciphertext each time (random IV)', async () => {
		const a = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		const b = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		expect(a).not.toBe(b);
	});

	it('uses the ivHex|:ciphertextHex format', async () => {
		const encrypted = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		expect(encrypted).toMatch(/^[0-9a-f]+\|:[0-9a-f]+$/);
	});

	it('fails to decrypt tampered ciphertext (GCM integrity check)', async () => {
		const encrypted = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		// Flip a bit in the ciphertext portion
		const tampered = encrypted.slice(0, -2) + (encrypted.slice(-2) === '00' ? '01' : '00');
		await expect(AvsEncryption.decryptString(tampered, TEST_KEY)).rejects.toThrow();
	});

	it('fails to decrypt with the wrong key', async () => {
		const encrypted = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		await expect(AvsEncryption.decryptString(encrypted, 'b'.repeat(32))).rejects.toThrow();
	});
});
```

- [ ] **Step 2: Run test — verify it fails (CBC tampering doesn't always throw)**

Run: `npx vitest run test/lib/encryption.test.ts`
Expected: the "fails to decrypt tampered ciphertext" test FAILS under CBC (CBC may not throw on single-bit flips if padding remains valid).

- [ ] **Step 3: Switch to AES-GCM in `src/lib/encryption.ts`**

In `src/lib/encryption.ts`:

Change `importKey` (line 23) `{ name: 'AES-CBC' }` → `{ name: 'AES-GCM' }`.

Change `encryptObject` (line 61-62):
```ts
		const encrypted = await crypto.subtle.encrypt(
			{ name: 'AES-GCM', iv },
			key,
			plaintext
		);
```

Change `decryptString` (line 91-92):
```ts
		const decrypted = await crypto.subtle.decrypt(
			{ name: 'AES-GCM', iv },
			key,
			encryptedData
		);
```

The IV size for GCM should be 12 bytes (recommended), not 16. Change line 57:
```ts
		const iv = crypto.getRandomValues(new Uint8Array(12));
```

- [ ] **Step 4: Run test — verify all pass**

Run: `npx vitest run test/lib/encryption.test.ts`
Expected: all 5 pass.

- [ ] **Step 5: Run full suite**

Run: `npx vitest run && npx tsc --noEmit`
Expected: all pass, no type errors.

- [ ] **Step 6: Commit**

```bash
git add src/lib/encryption.ts test/lib/encryption.test.ts
git commit -m "fix(high): switch AES-CBC to AES-GCM for authenticated encryption

AES-CBC without a MAC left all ciphertexts malleable (padding oracle +
bit-flipping). AES-GCM provides both confidentiality and integrity via
a built-in 16-byte authentication tag. IV size changed to 12 bytes
(GCM recommendation). Hard cutover — old CBC ciphertexts will fail to
decrypt and age out (payloads 10min, sessions 20min, cookies 30d)."
```

---

## Task 8: Key separation via HKDF (High #6)

**Files:**
- Create: `src/lib/crypto-utils.ts` (the `hkdfDerive` function)
- Create: `test/lib/crypto-utils.test.ts`
- Modify: `src/config.ts` (derive and expose `aesKey` + `hmacKey` as derived bytes)
- Modify: `src/lib/encryption.ts` (accept derived AES key bytes, not raw passphrase)
- Modify: `src/middleware/session.ts` (accept derived HMAC key bytes)

**Interfaces:**
- Consumes: `config.encryption.key` (the raw 32-byte passphrase)
- Produces:
  - `config.encryption.aesKey: Uint8Array` — HKDF-derived 32-byte AES key
  - `config.encryption.hmacKey: Uint8Array` — HKDF-derived 32-byte HMAC key (different from aesKey)
  - `AvsEncryption.encryptObject(obj, aesKey: Uint8Array)` / `decryptString(str, aesKey: Uint8Array)`
  - `signSessionId` / `verifySessionId` take `hmacKey: Uint8Array`

> **Note:** This task changes the signatures of `encryptObject`, `decryptString`, `signSessionId`, `verifySessionId`, `createSessionCookie`, and `getSessionContextFromRequest`. All call sites must be updated. This is the most invasive task — execute it carefully.

- [ ] **Step 1: Write the failing test for HKDF**

Create `test/lib/crypto-utils.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { hkdfDerive, constantTimeEqual } from '../../src/lib/crypto-utils';

describe('hkdfDerive', () => {
	it('produces 32-byte keys from a passphrase', async () => {
		const key = await hkdfDerive('a'.repeat(32), 'avs/aes/v1', 32);
		expect(key).toBeInstanceOf(Uint8Array);
		expect(key.byteLength).toBe(32);
	});

	it('produces different keys for different contexts', async () => {
		const aesKey = await hkdfDerive('a'.repeat(32), 'avs/aes/v1', 32);
		const hmacKey = await hkdfDerive('a'.repeat(32), 'avs/hmac/v1', 32);
		expect(aesKey).not.toEqual(hmacKey);
	});

	it('produces different keys for different passphrases', async () => {
		const k1 = await hkdfDerive('a'.repeat(32), 'avs/aes/v1', 32);
		const k2 = await hkdfDerive('b'.repeat(32), 'avs/aes/v1', 32);
		expect(k1).not.toEqual(k2);
	});
});

describe('constantTimeEqual', () => {
	it('returns true for equal strings', () => {
		expect(constantTimeEqual('abc123', 'abc123')).toBe(true);
	});

	it('returns false for unequal strings', () => {
		expect(constantTimeEqual('abc123', 'abc124')).toBe(false);
	});

	it('returns false for different lengths', () => {
		expect(constantTimeEqual('abc', 'ab')).toBe(false);
	});
});
```

- [ ] **Step 2: Run test — verify it fails**

Run: `npx vitest run test/lib/crypto-utils.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/lib/crypto-utils.ts`**

```ts
/**
 * Cryptographic utilities: HKDF key derivation + constant-time comparison.
 * Uses Web Crypto API (no Node dependencies).
 */

/**
 * Derive a purpose-bound subkey from a master passphrase using HKDF-SHA256.
 * Different `context` strings produce cryptographically independent keys,
 * enabling key separation (one derived key for AES, another for HMAC).
 */
export async function hkdfDerive(
	masterKey: string,
	context: string,
	length: number,
): Promise<Uint8Array> {
	const encoder = new TextEncoder();
	const baseKey = await crypto.subtle.importKey(
		'raw',
		encoder.encode(masterKey),
		'HKDF',
		false,
		['deriveBits'],
	);
	const bits = await crypto.subtle.deriveBits(
		{
			name: 'HKDF',
			hash: 'SHA-256',
			salt: encoder.encode('gocam-hkdf-salt-v1'),
			info: encoder.encode(context),
		},
		baseKey,
		length * 8,
	);
	return new Uint8Array(bits);
}

/**
 * Compare two strings in constant time (no early-exit on first mismatch).
 * Uses a manual XOR-accumulate so it does not depend on crypto.subtle.verify
 * (which would require importing an HMAC key).
 */
export function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	const encoder = new TextEncoder();
	const aBytes = encoder.encode(a);
	const bBytes = encoder.encode(b);
	let diff = 0;
	for (let i = 0; i < aBytes.byteLength; i++) {
		diff |= aBytes[i] ^ bBytes[i];
	}
	return diff === 0;
}
```

- [ ] **Step 4: Run test — verify it passes**

Run: `npx vitest run test/lib/crypto-utils.test.ts`
Expected: all 6 pass.

- [ ] **Step 5: Derive keys in `src/config.ts`**

`getConfig` is currently synchronous. HKDF is async. Change `getConfig` to `async function getConfig(env): Promise<AppConfig>` and derive keys:

Add to `AppConfig` interface:
```ts
export interface AppConfig {
	encryption: {
		key: string;       // raw passphrase (kept for backwards compat / logging)
		aesKey: Uint8Array; // HKDF-derived AES key
		hmacKey: Uint8Array; // HKDF-derived HMAC key
		algorithm: string;
	};
	// ... rest unchanged
}
```

In `getConfig` body (after the validation checks, before setting `_cachedConfig`):
```ts
	// NOTE: getConfig becomes async. HKDF keys are derived once and cached.
	const aesKey = await hkdfDerive(env.ENCRYPTION_KEY, 'avs/aes/v1', 32);
	const hmacKey = await hkdfDerive(env.ENCRYPTION_KEY, 'avs/hmac/v1', 32);
```

Add import: `import { hkdfDerive } from './lib/crypto-utils';`

> **IMPORTANT:** Because `getConfig` is called in every route handler, making it async means every call site must `await` it. All routes already call `getConfig(env)` — they need `await getConfig(env)`. Update: `src/routes/index.ts:16`, `src/routes/result.ts:57`, `src/routes/token.ts:51`. Also `src/index.ts` does NOT call getConfig directly (routes do).

- [ ] **Step 6: Update `src/lib/encryption.ts` to accept `Uint8Array` keys**

Change `importKey` to accept `Uint8Array` instead of a string:
```ts
	private static async importKey(keyBytes: Uint8Array): Promise<CryptoKey> {
		// Cache by a lightweight hash of the key bytes to avoid re-importing.
		const cacheKey = Array.from(keyBytes).join(',');
		let cached = AvsEncryption.keyCache.get(cacheKey);
		if (cached) return cached;
		const key = await crypto.subtle.importKey(
			'raw',
			keyBytes,
			{ name: 'AES-GCM' },
			false,
			['encrypt', 'decrypt']
		);
		AvsEncryption.keyCache.set(cacheKey, key);
		return key;
	}
```

Change `encryptObject` signature: `(object: object, keyBytes: Uint8Array)` and `const key = await AvsEncryption.importKey(keyBytes);`.

Change `decryptString` signature: `(encryptedString: string, keyBytes: Uint8Array)` and `const key = await AvsEncryption.importKey(keyBytes);`.

- [ ] **Step 7: Update `src/middleware/session.ts` to accept `Uint8Array` HMAC key**

Change `signSessionId(sessionId, hmacKey: Uint8Array)`:
```ts
async function signSessionId(sessionId: string, hmacKey: Uint8Array): Promise<string> {
	const encoder = new TextEncoder();
	const cacheKey = Array.from(hmacKey).join(',');
	let cryptoKey = hmacKeyCache.get(cacheKey);
	if (!cryptoKey) {
		cryptoKey = await crypto.subtle.importKey(
			'raw',
			hmacKey,
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign', 'verify']
		);
		hmacKeyCache.set(cacheKey, cryptoKey);
	}
	const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(sessionId));
	const sigHex = Array.from(new Uint8Array(signature))
		.map(b => b.toString(16).padStart(2, '0'))
		.join('');
	return `${sessionId}.${sigHex}`;
}
```

Update `verifySessionId(signedValue, hmacKey: Uint8Array)` accordingly (remove the dead code block from Task 23 as part of this, or keep it for now and remove in Task 23 — but since we're already editing, remove it now).

Update `getSessionContextFromRequest(request, hmacKey: Uint8Array)` and `createSessionCookie(payloadHash, requestSessionId, hmacKey: Uint8Array)`.

- [ ] **Step 8: Update all call sites**

In every route handler, change `const config = getConfig(env);` → `const config = await getConfig(env);`.

In every `AvsEncryption.encryptObject(..., config.encryption.key)` → `..., config.encryption.aesKey)`.
In every `AvsEncryption.decryptString(..., config.encryption.key)` → `..., config.encryption.aesKey)`.

In every `getSessionContextFromRequest(request, config.encryption.key)` → `..., config.encryption.hmacKey)`.
In every `createSessionCookie(..., config.encryption.key)` → `..., config.encryption.hmacKey)`.

In the DO (`src/durable-objects/verification-session.ts`), the key is read from `this.env.ENCRYPTION_KEY`. The DO must also derive keys. Add a cached derivation:
```ts
	private _aesKeyPromise: Promise<Uint8Array> | null = null;
	private async getAesKey(): Promise<Uint8Array> {
		if (!this._aesKeyPromise) {
			this._aesKeyPromise = hkdfDerive(this.env.ENCRYPTION_KEY, 'avs/aes/v1', 32);
		}
		return this._aesKeyPromise;
	}
```
Then replace `const encryptionKey = this.env.ENCRYPTION_KEY;` with `const aesKey = await this.getAesKey();` and pass `aesKey` to `encryptObject`/`decryptString`.

- [ ] **Step 9: Run full suite + typecheck**

Run: `npx vitest run && npx tsc --noEmit`
Expected: all pass, no type errors.

- [ ] **Step 10: Commit**

```bash
git add src/lib/crypto-utils.ts test/lib/crypto-utils.test.ts src/config.ts src/lib/encryption.ts src/middleware/session.ts src/routes/index.ts src/routes/result.ts src/routes/token.ts src/durable-objects/verification-session.ts test/lib/encryption.test.ts
git commit -m "fix(high): separate AES and HMAC keys via HKDF

Previously one ENCRYPTION_KEY was used for both AES encryption and HMAC
cookie signing. Now HKDF-SHA256 derives independent 32-byte subkeys:
'avs/aes/v1' for encryption, 'avs/hmac/v1' for signing. Also adds
constantTimeEqual() for use in Task 14. getConfig is now async."
```

---

## Task 9: `payloadHash` → real SHA-256 hash (High #7)

**Files:**
- Create: `test/lib/encryption.test.ts` (add to existing)
- Modify: `src/lib/encryption.ts` (add `computePayloadHash`)
- Modify: `src/durable-objects/verification-session.ts` (use real hash)
- Modify: `src/routes/token.ts` (use real hash)
- Modify: `src/routes/result.ts` (use real hash)

**Interfaces:**
- Produces: `AvsEncryption.computePayloadHash(payloadCiphertext: string): string` — returns SHA-256 hex of the full ciphertext (64 chars). Stable regardless of IV randomness.

- [ ] **Step 1: Write the failing test**

Add to `test/lib/encryption.test.ts`:
```ts
	describe('computePayloadHash', () => {
		it('returns a 64-char hex string', async () => {
			const hash = AvsEncryption.computePayloadHash('abc123|:deadbeef');
			expect(hash).toMatch(/^[0-9a-f]{64}$/);
		});

		it('is deterministic for the same ciphertext', () => {
			expect(AvsEncryption.computePayloadHash('abc123|:deadbeef'))
				.toBe(AvsEncryption.computePayloadHash('abc123|:deadbeef'));
		});

		it('differs for different ciphertexts', () => {
			expect(AvsEncryption.computePayloadHash('abc123|:deadbeef'))
				.not.toBe(AvsEncryption.computePayloadHash('abc123|:cafebabe'));
		});
	});
```

- [ ] **Step 2: Run test — verify it fails**

Run: `npx vitest run test/lib/encryption.test.ts`
Expected: FAIL — `computePayloadHash` not a function.

- [ ] **Step 3: Implement `computePayloadHash` in `src/lib/encryption.ts`**

Add as a static method:
```ts
	/**
	 * Compute a SHA-256 hash of the payload ciphertext.
	 * This is a content-addressable identifier — the same ciphertext always
	 * produces the same hash, regardless of the random IV embedded in it.
	 * Used for DO routing, dedup, and session identity.
	 */
	static async computePayloadHash(ciphertext: string): Promise<string> {
		const data = AvsEncryption.encoder.encode(ciphertext);
		const hashBuffer = await crypto.subtle.digest('SHA-256', data);
		return AvsEncryption.bytesToHex(new Uint8Array(hashBuffer));
	}
```

> Note: because this is async, all callers that did `payload.substring(0, 64)` must now `await AvsEncryption.computePayloadHash(payload)`. The DO `startSession` already async; token.ts `renderTokenPage` already async; result.ts handlers already async.

- [ ] **Step 4: Update DO `startSession`**

In `src/durable-objects/verification-session.ts` line 217:
```ts
		const payloadHash = await AvsEncryption.computePayloadHash(payload);
```

In `endSession` line 312:
```ts
				sessionData.payload ? await AvsEncryption.computePayloadHash(sessionData.payload) : null,
```

In `updateState` line 360:
```ts
				sessionData.payload ? await AvsEncryption.computePayloadHash(sessionData.payload) : null,
```
Note: `updateState` is currently sync (`private updateState(...)`). It must become `private async updateState(...)` and the `await` at the call site (DO `fetch` switch line 177) must be added.

- [ ] **Step 5: Update `src/routes/token.ts`**

Line 104:
```ts
	const payloadHash = await AvsEncryption.computePayloadHash(payload);
```
Add import: `import { AvsEncryption } from '../lib/encryption';` (already present).

- [ ] **Step 6: Update `src/routes/result.ts`**

In `/result/isSuccess` (lines 270-275), change the payloadHash derivation:
```ts
		let payloadHash: string;
		if (sessionContext) {
			payloadHash = sessionContext.payloadHash;
		} else {
			payloadHash = payload ? await AvsEncryption.computePayloadHash(payload) : '';
		}
```
Add import for `AvsEncryption`.

- [ ] **Step 7: Run full suite + typecheck**

Run: `npx vitest run && npx tsc --noEmit`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add src/lib/encryption.ts test/lib/encryption.test.ts src/durable-objects/verification-session.ts src/routes/token.ts src/routes/result.ts
git commit -m "fix(high): payloadHash is now a real SHA-256 hash, not a ciphertext prefix

Previously payloadHash was payload.substring(0,64) — the first 64 chars
of the ciphertext, which is the random IV. Re-encrypting the same payload
produced a different hash, defeating the 'link already used' dedup.
Now uses SHA-256 of the full ciphertext: deterministic, collision-resistant."
```

---

## Task 10: Stop scrubbing real IP/country in endSession (High #8)

**Files:**
- Modify: `src/durable-objects/verification-session.ts:328-332`

- [ ] **Step 1: Remove the hardcoded overrides**

In `endSession`, replace lines 329-332:
```ts
		decryptedPayload.userIpStr          = '127.0.0.1';
		decryptedPayload.userIpCountry      = 'A1';
		decryptedPayload.userData           = sessionData.userData;
		decryptedPayload.callbackUrl        = '';
```
with:
```ts
		decryptedPayload.userData           = sessionData.userData;
		decryptedPayload.callbackUrl        = '';
```

(Keep the `callbackUrl = ''` redaction — that's intentional. Keep the `userData` update. Remove the IP/country overrides so the real values from the session are preserved.)

- [ ] **Step 2: Typecheck**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/durable-objects/verification-session.ts
git commit -m "fix(high): preserve real user IP/country in verified payload

endSession was overwriting the user's real IP with 127.0.0.1 and country
with A1 (anonymous proxy) before re-encrypting the success payload.
This was a debug leftover that caused partners to see bogus location
data for verified users."
```

---

## Task 11: Callback retry + status tracking (High #9)

**Files:**
- Modify: `src/durable-objects/verification-session.ts` (schema migration + `dispatchCallback` + `endSession`)

**Interfaces:**
- Produces: `sessions` table gets a `callbackStatus` column (`pending`/`sent`/`failed`). `dispatchCallback` updates it. DO alarm retries failed callbacks.

- [ ] **Step 1: Add `callbackStatus` column to schema**

In `ensureInitialized`, add to the `sessions` CREATE TABLE (after `createdAt`):
```sql
					callbackStatus TEXT DEFAULT 'pending'
```

Since this is a new column, add a migration after the CREATE statements:
```sql
				-- Migration: add callbackStatus column if missing
```
Use a try/exec approach:
```ts
			try {
				this.ctx.storage.sql.exec(`ALTER TABLE sessions ADD COLUMN callbackStatus TEXT DEFAULT 'pending'`);
			} catch {
				// Column already exists
			}
```

- [ ] **Step 2: Set `callbackStatus = 'pending'` in `endSession` before dispatching**

In `endSession`, before the `ctx.waitUntil(dispatchCallback(...))` call, the INSERT OR REPLACE already writes the session. Update it to set `callbackStatus`. Add `callbackStatus: 'pending'` to the session write. Since we write `JSON.stringify(sessionData)`, add it to `sessionData`:
```ts
		sessionData.callbackStatus = 'pending';
```

- [ ] **Step 3: Update `dispatchCallback` to set status**

In `dispatchCallback`, after a successful fetch:
```ts
				this.updateCallbackStatus(sessionId, 'sent');
```
In the catch block:
```ts
			this.updateCallbackStatus(sessionId, 'failed');
```

Add the helper:
```ts
	private updateCallbackStatus(sessionId: string, status: 'pending' | 'sent' | 'failed'): void {
		const sessionData = this.getById(sessionId);
		if (!sessionData) return;
		sessionData.callbackStatus = status;
		const payloadHash = sessionData.payload ? undefined : undefined; // already computed elsewhere
		this.ctx.storage.sql.exec(
			`UPDATE sessions SET data = ? WHERE sessionId = ?`,
			JSON.stringify(sessionData),
			sessionId
		);
	}
```

- [ ] **Step 4: Add alarm-based retry**

In the DO class, add an `alarm()` method:
```ts
	async alarm(): Promise<void> {
		this.ensureInitialized();
		// Retry failed/pending callbacks
		const cursor = this.ctx.storage.sql.exec(
			`SELECT sessionId, data FROM sessions WHERE callbackStatus = 'failed' OR callbackStatus = 'pending'`
		);
		for (const row of cursor) {
			const sessionData = JSON.parse(row.data as string) as SessionData;
			if (sessionData.callbackUrl && sessionData.stateInt === SESSION_STATE_SUCCESS) {
				await this.dispatchCallback(sessionData, sessionData.stateInt, sessionData.sessionId, sessionData.errorCode || 0, sessionData.stepIp || 0, sessionData.idCountry || '', sessionData.idState || '', sessionData.idType || '');
			}
		}
	}
```

In `endSession`, after `ctx.waitUntil(dispatchCallback(...))`, schedule an alarm as a fallback:
```ts
		// Schedule a retry alarm in 60 seconds
		this.ctx.storage.setAlarm(Date.now() + 60_000);
```

- [ ] **Step 5: Add terminal-state guard to prevent re-ending**

At the top of `endSession` (after fetching sessionData), add:
```ts
		// Prevent re-ending an already-terminal session
		if (sessionData.stateInt === SESSION_STATE_SUCCESS || sessionData.stateInt === SESSION_STATE_FAILED) {
			// Return the existing payload (re-encrypt)
			const decryptedPayload = await AvsEncryption.decryptString(sessionData.payload, aesKey);
			decryptedPayload.verificationResult = {
				state:    STATE_MAP[sessionData.stateInt],
				stateInt: sessionData.stateInt,
				sessionId,
				errorCode: sessionData.errorCode || 0,
			};
			return { payload: await AvsEncryption.encryptObject(decryptedPayload, aesKey) };
		}
```

- [ ] **Step 6: Typecheck**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/durable-objects/verification-session.ts
git commit -m "fix(high): track callback status and retry failed callbacks

Adds callbackStatus column (pending/sent/failed) to the sessions table.
Failed or pending callbacks are retried via a DO alarm 60s after
session end. Also prevents re-ending an already-terminal session
(avoiding duplicate partner callbacks + duplicate cookie minting)."
```

---

## Task 12: Rate limiting via Cloudflare Rate Limiting binding (High #10)

**Files:**
- Modify: `wrangler.jsonc` (add rate limiting binding)
- Modify: `src/index.ts` (check rate limit on POST endpoints)

**Interfaces:**
- Produces: `env.RATE_LIMITER` (Durable Object-based rate limiter). A `checkRateLimit(env, request)` helper returns `true` if allowed.

- [ ] **Step 1: Add rate limiting binding to `wrangler.jsonc`**

Add to `wrangler.jsonc` (in the bindings area):
```jsonc
	"unsafe": {
		"bind_": []
	},
```

> Actually, Cloudflare Rate Limiting uses a different config. Add:
```jsonc
	// Rate limiting for unauthenticated endpoints
	"limits": [
		{
			"name": "api-rate-limit",
			"npcd": false,
			"rules": [
				{
					"action": "block",
					"characteristics": ["ip.src", "request.headers['user-agent']"],
					"matching": "(http.request.method in ['POST'])",
					"period": 60,
					"requests_per_period": 30,
					"mitigation_timeout": 120
				}
			]
		}
	]
```

> **Note:** Cloudflare's declarative rate limiting is configured via the dashboard or `wrangler.jsonc` under the top-level `"limits"` key (beta). If this key isn't supported by the installed wrangler version, the fallback is to enforce rate limiting inside the Worker using the DO. For this task, use the simpler in-Worker approach to avoid wrangler version issues:

**Fallback in-Worker rate limit (recommended for portability):**

In `src/index.ts`, add a simple IP-based rate limit using a `Map<string, {count, resetAt}>` at module scope. This is per-isolate (not global), so it's a best-effort throttle. Document this limitation.

Add to `src/index.ts`:
```ts
// Per-isolate rate limiting (best-effort; for production use Cloudflare Rate Limiting rules)
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 30;

function checkRateLimit(ip: string): boolean {
	const now = Date.now();
	let entry = rateLimitMap.get(ip);
	if (!entry || now > entry.resetAt) {
		entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
		rateLimitMap.set(ip, entry);
	}
	entry.count++;
	// Periodic cleanup
	if (rateLimitMap.size > 10_000) {
		for (const [key, val] of rateLimitMap) {
			if (now > val.resetAt) rateLimitMap.delete(key);
		}
	}
	return entry.count <= RATE_LIMIT_MAX_REQUESTS;
}
```

In the `fetch` handler, after OPTIONS handling, before routing:
```ts
		if (request.method === 'POST') {
			const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
			if (!checkRateLimit(clientIp)) {
				return new Response(JSON.stringify({ error: 'rate_limited' }), {
					status: 429,
					headers: { 'Content-Type': 'application/json', 'Retry-After': '60' },
				});
			}
		}
```

- [ ] **Step 2: Commit**

```bash
git add src/index.ts
git commit -m "fix(high): add per-isolate rate limiting for POST endpoints

Best-effort IP-based throttle (30 requests/60s per IP per isolate).
For production-grade limiting, configure Cloudflare Rate Limiting
rules at the edge."
```

---

## Task 13: Security headers (High #11)

**Files:**
- Modify: `src/index.ts:45-58` (`addSecurityHeaders`)

- [ ] **Step 1: Add security headers to `addSecurityHeaders`**

In `src/index.ts`, extend `addSecurityHeaders`:
```ts
		const addSecurityHeaders = (response: Response): Response => {
			const newHeaders = new Headers(response.headers);
			newHeaders.set(
				'Permissions-Policy',
				'publickey-credentials-get=(self), publickey-credentials-create=(self), camera=(self)'
			);
			newHeaders.set('Access-Control-Allow-Origin', '*');
			newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
			newHeaders.set('X-Content-Type-Options', 'nosniff');
			newHeaders.set('Referrer-Policy', 'no-referrer');
			newHeaders.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
			newHeaders.set(
				'Content-Security-Policy',
				"default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; frame-ancestors *;"
			);
			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: newHeaders,
			});
		};
```

> **Note on `frame-ancestors`:** The app is iframe-embedded by partners, so `frame-ancestors *` allows any origin to embed. For production, this should be a partner allowlist. `*` is used here because we don't have a partner list. Document this.

- [ ] **Step 2: Typecheck**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/index.ts
git commit -m "fix(high): add security headers (CSP, HSTS, nosniff, Referrer-Policy)

CSP restricts script/style/font/img sources. HSTS enforces HTTPS.
X-Content-Type-Options prevents MIME sniffing. Referrer-Policy set
to no-referrer. frame-ancestors is * (partner allowlist TBD)."
```

---

## Task 14: Constant-time token comparison (High #12)

**Files:**
- Modify: `src/routes/result.ts` (the `tokenIsValid` function from Task 2)

- [ ] **Step 1: Update `tokenIsValid` to use `constantTimeEqual`**

In `src/routes/result.ts`, update the import and function:
```ts
import { constantTimeEqual } from '../lib/crypto-utils';
```

Change `tokenIsValid`:
```ts
export function tokenIsValid(token: unknown, storedKey: string | undefined): boolean {
	if (typeof storedKey !== 'string' || typeof token !== 'string') return false;
	return constantTimeEqual(token, storedKey);
}
```

- [ ] **Step 2: Update the test to verify both functions still work**

The tests from Task 2 should still pass unchanged.

Run: `npx vitest run test/routes/result.test.ts`
Expected: 4 pass.

- [ ] **Step 3: Commit**

```bash
git add src/routes/result.ts
git commit -m "fix(high): use constant-time comparison for token verification

successKey/failKey comparison was using === which short-circuits on
first mismatch (timing side-channel). Now uses constantTimeEqual()
which XOR-accumulates all bytes before returning."
```

---

## Task 15: Fail-closed IP/country defaults (High #13)

**Files:**
- Modify: `src/routes/index.ts:81-87`

- [ ] **Step 1: Replace defaults with fail-closed**

In `src/routes/index.ts`, replace lines 81-87:
```ts
		const requestCf = request.cf as { country?: string; regionCode?: string } | undefined;
		const userIpCountry = requestCf?.country;
		const userIpState = requestCf?.regionCode;
		const userIp = request.headers.get('CF-Connecting-IP');

		if (!userIpCountry || !userIpState || !userIp) {
			return Response.json(AvsResponse.errorResponse(30000, 'Unable to determine client location. This service must be accessed via the Cloudflare edge.'));
		}
```

- [ ] **Step 2: Typecheck**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/routes/index.ts
git commit -m "fix(high): fail closed when client IP/country unavailable

Previously defaulted to US/TX/127.0.0.1 when request.cf or
CF-Connecting-IP was absent, silently treating unknown clients as
US residents (age 18). Now rejects the request."
```

---

## Task 16: Wrap unprotected `callDoJson` + extract shared helper (High #14)

**Files:**
- Create: `src/lib/do.ts`
- Create: `test/lib/do.test.ts`
- Modify: `src/routes/result.ts`, `src/routes/token.ts` (remove local copies, import shared)

**Interfaces:**
- Produces: `callDoJson<T>(stub, action, body): Promise<T>` in `src/lib/do.ts`.

- [ ] **Step 1: Write the test**

Create `test/lib/do.test.ts`:
```ts
import { describe, it, expect, vi } from 'vitest';
import { callDoJson } from '../../src/lib/do';

describe('callDoJson', () => {
	it('returns parsed JSON on success', async () => {
		const stub = {
			fetch: vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 })),
		};
		const result = await callDoJson<{ ok: boolean }>(stub as any, 'test', {});
		expect(result).toEqual({ ok: true });
	});

	it('throws on non-OK status', async () => {
		const stub = {
			fetch: vi.fn().mockResolvedValue(new Response('error', { status: 500 })),
		};
		await expect(callDoJson(stub as any, 'test', {})).rejects.toThrow(/failed/);
	});

	it('throws when response has error field', async () => {
		const stub = {
			fetch: vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: 'bad' }), { status: 200 })),
		};
		await expect(callDoJson(stub as any, 'test', {})).rejects.toThrow(/failed/);
	});

	it('includes HTTP status in the error message', async () => {
		const stub = {
			fetch: vi.fn().mockResolvedValue(new Response('error', { status: 503 })),
		};
		await expect(callDoJson(stub as any, 'test', {})).rejects.toThrow(/503/);
	});
});
```

- [ ] **Step 2: Implement `src/lib/do.ts`**

```ts
import type { getDoStub } from '../middleware/session';

type DoStub = ReturnType<typeof getDoStub>;

/**
 * Call a Durable Object action and parse the JSON response.
 * Throws on non-OK status or when the response contains an `error` field.
 * The error message includes the HTTP status (not the body, which may leak internals).
 */
export async function callDoJson<T>(
	stub: DoStub,
	action: string,
	body: Record<string, unknown>,
): Promise<T> {
	const response = await stub.fetch(
		new Request(`http://do/${action}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
		}),
	);

	let json: any = null;
	try {
		json = await response.json();
	} catch {
		throw new Error(`DO action "${action}" returned invalid JSON (HTTP ${response.status})`);
	}

	if (!response.ok || (json && typeof json === 'object' && typeof json.error !== 'undefined')) {
		throw new Error(`DO action "${action}" failed (HTTP ${response.status})`);
	}

	return json as T;
}
```

- [ ] **Step 3: Remove the duplicated `callDoJson` from both route files**

In `src/routes/result.ts`: remove lines 27-52 (the local `callDoJson`), add:
```ts
import { callDoJson } from '../lib/do';
```

In `src/routes/token.ts`: remove lines 21-46 (the local `callDoJson`), add:
```ts
import { callDoJson } from '../lib/do';
```

- [ ] **Step 4: Wrap previously-unprotected `callDoJson` calls in result.ts**

Wrap the `end` and `updateState` calls in try/catch. In `/result/success`, the `end` call (line ~145):
```ts
		let endResult: any;
		try {
			endResult = await callDoJson<{ payload: string } | null>(stub, 'end', { ... });
		} catch (err) {
			console.error('DO end error:', err);
			return Response.json(AvsResponse.errorResponse(30010, 'Failed to save session data'));
		}
```
Apply similar try/catch to the `updateState` calls and the `/result/fail` path.

- [ ] **Step 5: Run tests + typecheck**

Run: `npx vitest run && npx tsc --noEmit`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/lib/do.ts test/lib/do.test.ts src/routes/result.ts src/routes/token.ts
git commit -m "fix(high): extract shared callDoJson and wrap unprotected calls

Removes byte-for-byte duplicate callDoJson from result.ts and token.ts.
Shared helper includes HTTP status in error messages. Previously-
unprotected end/updateState calls are now wrapped in try/catch to
return structured errors instead of bare 500s."
```

---

## Task 17: `isAgeVerified` cookie hardening (Medium)

**Files:**
- Modify: `src/config.ts` (cookie config)
- Modify: `src/routes/result.ts:163`

- [ ] **Step 1: Update cookie config in `src/config.ts`**

Change `cookie` block (lines 47-51):
```ts
		cookie: {
			httpOnly: true,
			secure: true,
			sameSite: 'Lax',
			maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms (was 30 days)
		},
```

Add `sameSite` to the interface:
```ts
	cookie: {
		httpOnly: boolean;
		secure: boolean;
		sameSite: 'Lax' | 'Strict' | 'None';
		maxAge: number;
	};
```

- [ ] **Step 2: Update cookie string in `src/routes/result.ts`**

Replace line 163:
```ts
		const cookieValue = `isAgeVerified=${successPayload}; Path=/; Max-Age=${config.cookie.maxAge / 1000}; Secure; HttpOnly; SameSite=${config.cookie.sameSite}`;
```

- [ ] **Step 3: Typecheck**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add src/config.ts src/routes/result.ts
git commit -m "fix(medium): harden isAgeVerified cookie (HttpOnly, SameSite, 7-day TTL)

Cookie was non-HttpOnly (XSS-stealable), had no SameSite attribute,
and lived 30 days. Now HttpOnly, SameSite=Lax, 7-day TTL."
```

---

## Task 18: `/result/isSuccess` require session cookie (Medium)

**Files:**
- Modify: `src/routes/result.ts:264-284`

- [ ] **Step 1: Require session cookie**

Replace the `/result/isSuccess` block:
```ts
	// POST /result/isSuccess
	if (pathname === '/result/isSuccess') {
		if (!sessionContext) {
			return Response.json(AvsResponse.errorResponse(30010, 'Session not found'));
		}

		const stub = getDoStub(env, sessionContext.payloadHash);
		let checkResult: any;
		try {
			checkResult = await callDoJson<{ isValidated: boolean }>(stub, 'isPayloadValidated', {
				payloadHash: sessionContext.payloadHash,
			});
		} catch (err) {
			console.error('DO isPayloadValidated error:', err);
			return Response.json(AvsResponse.errorResponse(30010, 'Session lookup failed'));
		}

		return Response.json(AvsResponse.successResponse({
			isValidated: checkResult?.isValidated || false,
		}));
	}
```

- [ ] **Step 2: Typecheck + test**

Run: `npx tsc --noEmit && npx vitest run`
Expected: pass.

- [ ] **Step 3: Commit**

```bash
git add src/routes/result.ts
git commit -m "fix(medium): require signed session cookie for /result/isSuccess

Endpoint was pollable without a cookie, using an attacker-supplied
payload prefix. Now requires the signed avs-session cookie and uses
only the cookie's payloadHash."
```

---

## Task 19: CORS allowlist (Medium)

**Files:**
- Modify: `src/index.ts`

**Interfaces:**
- Produces: a `getCorsOrigin(request)` helper that returns the allowed origin or `null`.

- [ ] **Step 1: Replace `Access-Control-Allow-Origin: *`**

In `src/index.ts`, add a helper:
```ts
	// Allowed origins for CORS. Add partner domains here.
	const ALLOWED_ORIGINS = new Set([
		// Partner origins go here. Example:
		// 'https://partner1.example.com',
	]);

	function getAllowedOrigin(request: Request): string | null {
		const origin = request.headers.get('Origin');
		if (!origin) return null;
		if (ALLOWED_ORIGINS.has(origin)) return origin;
		// Same-origin (no Origin header on same-site requests) — allow implicitly
		return null;
	}
```

Update OPTIONS preflight:
```ts
		if (request.method === 'OPTIONS') {
			const allowedOrigin = getAllowedOrigin(request);
			const headers: Record<string, string> = {
				'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
				'Access-Control-Allow-Headers': 'Content-Type',
				'Access-Control-Max-Age': '86400',
			};
			if (allowedOrigin) {
				headers['Access-Control-Allow-Origin'] = allowedOrigin;
				headers['Vary'] = 'Origin';
			}
			return new Response(null, { status: 204, headers });
		}
```

Update `addSecurityHeaders`:
```ts
		const addSecurityHeaders = (response: Response): Response => {
			const newHeaders = new Headers(response.headers);
			// ... other headers ...
			const allowedOrigin = getAllowedOrigin(request);
			if (allowedOrigin) {
				newHeaders.set('Access-Control-Allow-Origin', allowedOrigin);
				newHeaders.set('Vary', 'Origin');
			}
			// ... rest ...
		};
```

- [ ] **Step 2: Typecheck**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/index.ts
git commit -m "fix(medium): replace CORS * with partner-origin allowlist

CORS was Access-Control-Allow-Origin: * on every response. Now reflects
the request Origin only if it matches the ALLOWED_ORIGINS set.
Partners must be added to the allowlist."
```

---

## Task 20: Define payload types + validate decrypted data (Medium)

**Files:**
- Create: `src/lib/types.ts`
- Create: `test/lib/types.test.ts`
- Modify: `src/lib/encryption.ts` (`decryptString` return type)
- Modify: `src/durable-objects/verification-session.ts`, `src/routes/index.ts`, `src/routes/token.ts` (consume typed result)

**Interfaces:**
- Produces: `DecryptedPayload` interface, `isDecryptedPayload(v): v is DecryptedPayload` type guard. `decryptString` returns `Promise<DecryptedPayload>`.

- [ ] **Step 1: Write the failing test**

Create `test/lib/types.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { isDecryptedPayload } from '../../src/lib/types';

describe('isDecryptedPayload', () => {
	it('accepts a well-formed payload', () => {
		expect(isDecryptedPayload({
			userData: {}, websiteHostname: 'example.com', callbackUrl: 'https://x.com',
			creationTimestamp: Date.now(), userIpStr: '1.2.3.4', userIpCountry: 'US',
		})).toBe(true);
	});

	it('rejects null', () => {
		expect(isDecryptedPayload(null)).toBe(false);
	});

	it('rejects missing callbackUrl', () => {
		expect(isDecryptedPayload({ userData: {} })).toBe(false);
	});
});
```

- [ ] **Step 2: Implement `src/lib/types.ts`**

```ts
export interface VerificationResult {
	state: string;
	stateInt: number;
	sessionId: string;
	errorCode: number;
}

export interface DecryptedPayload {
	userData: Record<string, any>;
	httpUserAgent?: string;
	websiteHostname: string;
	httpParamList?: Record<string, any>;
	verificationVersion?: number;
	linkBack?: string;
	userIpCountry: string;
	userIpState?: string;
	userIpStr: string;
	callbackUrl: string;
	creationTimestamp: number;
	verificationResult?: VerificationResult;
}

export function isDecryptedPayload(v: unknown): v is DecryptedPayload {
	if (typeof v !== 'object' || v === null) return false;
	const obj = v as Record<string, unknown>;
	return (
		typeof obj.userData === 'object' ||
		typeof obj.websiteHostname === 'string' ||
		typeof obj.callbackUrl === 'string' ||
		typeof obj.creationTimestamp === 'number'
	);
}
```

- [ ] **Step 3: Update `decryptString` return type**

In `src/lib/encryption.ts`, change the signature:
```ts
	static async decryptString(encryptedString: string, keyBytes: Uint8Array): Promise<DecryptedPayload> {
```
Add import: `import type { DecryptedPayload } from './types';`

- [ ] **Step 4: Run tests + typecheck**

Run: `npx vitest run && npx tsc --noEmit`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add src/lib/types.ts test/lib/types.test.ts src/lib/encryption.ts
git commit -m "fix(medium): define DecryptedPayload type and type decryptString

decryptString returned any, so no field was type-checked. Now returns
DecryptedPayload with a runtime type guard isDecryptedPayload()."
```

---

## Task 21: Safe parseInt helper + NaN guards (Medium)

**Files:**
- Create: `src/lib/parse.ts`
- Create: `test/lib/parse.test.ts`
- Modify: `src/routes/result.ts`

- [ ] **Step 1: Write the failing test**

Create `test/lib/parse.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { safeParseInt } from '../../src/lib/parse';

describe('safeParseInt', () => {
	it('parses a valid integer string', () => {
		expect(safeParseInt('42', 0)).toBe(42);
	});

	it('returns default for non-numeric', () => {
		expect(safeParseInt('abc', 0)).toBe(0);
	});

	it('returns default for NaN input', () => {
		expect(safeParseInt(NaN, 5)).toBe(5);
	});

	it('returns default for undefined', () => {
		expect(safeParseInt(undefined, 0)).toBe(0);
	});

	it('ignores trailing garbage', () => {
		expect(safeParseInt('3<script>', 0)).toBe(0);
	});
});
```

- [ ] **Step 2: Implement `src/lib/parse.ts`**

```ts
/**
 * Safely parse an integer from unknown input.
 * Returns the default if the input is not a clean integer.
 * Unlike parseInt, rejects trailing garbage like "3abc".
 */
export function safeParseInt(value: unknown, defaultValue: number = 0): number {
	if (typeof value === 'number') {
		return Number.isFinite(value) ? Math.trunc(value) : defaultValue;
	}
	if (typeof value !== 'string') return defaultValue;
	const trimmed = value.trim();
	if (!/^-?\d+$/.test(trimmed)) return defaultValue;
	const n = parseInt(trimmed, 10);
	return Number.isFinite(n) ? n : defaultValue;
}
```

- [ ] **Step 3: Replace `parseInt` calls in `src/routes/result.ts`**

Add import: `import { safeParseInt } from '../lib/parse';`

Replace all `parseInt(body.xxx || '0')` → `safeParseInt(body.xxx, 0)` in both `/result/success` and `/result/fail`.

- [ ] **Step 4: Run tests**

Run: `npx vitest run test/lib/parse.test.ts`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/lib/parse.ts test/lib/parse.test.ts src/routes/result.ts
git commit -m "fix(medium): replace parseInt with safeParseInt (NaN guard)

parseInt('abc') returns NaN, which made deviceLocationVerification
comparisons behave unexpectedly. safeParseInt rejects non-clean
integers and returns a default."
```

---

## Task 22: Body-parse — reject malformed with 400 (Medium)

**Files:**
- Modify: `src/routes/result.ts:62-73`, `src/routes/index.ts` (`/callback`, `/validateVerificationPayload`)

- [ ] **Step 1: Replace silent `{}` fallback with explicit rejection**

In `src/routes/result.ts`, replace lines 62-73:
```ts
	// Parse body — reject malformed requests with 400
	let body: any;
	try {
		const contentType = request.headers.get('Content-Type') || '';
		if (contentType.includes('application/json')) {
			body = await request.json();
		} else {
			const formData = await request.formData();
			body = Object.fromEntries(formData);
		}
		if (!body || typeof body !== 'object') {
			return Response.json(AvsResponse.errorResponse(30000, 'Invalid request body'), { status: 400 });
		}
	} catch {
		return Response.json(AvsResponse.errorResponse(30000, 'Malformed request body'), { status: 400 });
	}
```

In `src/routes/index.ts` `/callback` handler, apply the same pattern (reject with 400 instead of `{}`).

In `/validateVerificationPayload`, wrap the `request.json()` in try/catch and return 400 on failure.

- [ ] **Step 2: Typecheck**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/routes/result.ts src/routes/index.ts
git commit -m "fix(medium): reject malformed request bodies with 400 instead of {}

Malformed JSON was silently becoming {}, masking abusive/malformed
traffic. Now returns a 400 error."
```

---

## Task 23: Remove dead code in `verifySessionId` (Medium)

**Files:**
- Modify: `src/middleware/session.ts:59-103`

> Note: If Task 8 (HKDF) already cleaned this up during the key-signature change, skip this task. Check first.

- [ ] **Step 1: Remove the dead re-sign/compare block**

In `verifySessionId`, remove the block that re-signs and compares byte lengths (the code between the dotIndex split and the `crypto.subtle.verify` call). The function should be:

```ts
async function verifySessionId(signedValue: string, hmacKey: Uint8Array): Promise<string | null> {
	const dotIndex = signedValue.lastIndexOf('.');
	if (dotIndex === -1) return null;

	const sessionId = signedValue.substring(0, dotIndex);
	const signatureHex = signedValue.substring(dotIndex + 1);

	// Validate signature format (64 hex chars)
	if (!/^[0-9a-f]{64}$/.test(signatureHex)) return null;

	const enc = new TextEncoder();
	let cryptoKey = hmacKeyCache.get(Array.from(hmacKey).join(','));
	if (!cryptoKey) {
		cryptoKey = await crypto.subtle.importKey(
			'raw',
			hmacKey,
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign', 'verify']
		);
		hmacKeyCache.set(Array.from(hmacKey).join(','), cryptoKey);
	}

	const sigBytes = new Uint8Array(signatureHex.length / 2);
	for (let i = 0; i < signatureHex.length; i += 2) {
		sigBytes[i / 2] = parseInt(signatureHex.substring(i, i + 2), 16);
	}

	const valid = await crypto.subtle.verify('HMAC', cryptoKey, sigBytes, enc.encode(sessionId));
	return valid ? sessionId : null;
}
```

- [ ] **Step 2: Typecheck + test**

Run: `npx tsc --noEmit && npx vitest run`
Expected: pass.

- [ ] **Step 3: Commit**

```bash
git add src/middleware/session.ts
git commit -m "fix(medium): remove dead code in verifySessionId

The re-sign + manual byte-length comparison block was never used (the
actual verification is crypto.subtle.verify). Removed dead code and
added hex-format validation."
```

---

## Task 24: Rewrite stale README (Medium)

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rewrite README to reflect the Workers port**

Replace the stale scripts/project-structure sections. Key content:
- Title: Go.cam Age Verification — Cloudflare Workers Edition
- Prerequisites: Node.js 18+, npm
- Setup: `npm install`, set secrets via `wrangler secret put ENCRYPTION_KEY` (generate with `node -e "console.log(require('crypto').randomBytes(32).toString('latin1'))"`)
- Dev: `npm run dev`
- Deploy: `npm run deploy`
- Type check: `npm run types`
- Tests: `npm test`
- Project structure: `src/` (Worker), `app/frontend` (static assets), `wrangler.jsonc` (config)

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README for Cloudflare Workers port

Old README documented Node.js/Express scripts that no longer exist.
Now reflects wrangler dev/deploy, Workers secrets, and the src/ layout."
```

---

## Task 25: `escapeHtml` add `'`; JSON-in-script add U+2028/U+2029 (Medium)

**Files:**
- Modify: `src/templates/token-error.ts:29-35`
- Modify: `src/templates/home.ts:250-256`
- Modify: `src/templates/base.ts:17`
- Modify: `src/templates/token-embed-check.ts:14`

- [ ] **Step 1: Add `'` escaping to both `escapeHtml` functions**

In `src/templates/token-error.ts` and `src/templates/home.ts`, add `.replace(/'/g, '&#39;')`:
```ts
function escapeHtml(str: string): string {
	return str
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}
```

- [ ] **Step 2: Add U+2028/U+2029 escaping to JSON-in-script**

In `src/templates/base.ts` line 17:
```ts
	const jsDataJson = JSON.stringify(js)
		.replace(/</g, '\\u003c')
		.replace(/\u2028/g, '\\u2028')
		.replace(/\u2029/g, '\\u2029');
```

In `src/templates/token-embed-check.ts` line 14:
```ts
	const jsDataJson = JSON.stringify(options.js)
		.replace(/</g, '\\u003c')
		.replace(/\u2028/g, '\\u2028')
		.replace(/\u2029/g, '\\u2029');
```

- [ ] **Step 3: Commit**

```bash
git add src/templates/token-error.ts src/templates/home.ts src/templates/base.ts src/templates/token-embed-check.ts
git commit -m "fix(medium): harden HTML/JSON escaping in templates

escapeHtml now escapes single quotes (for attribute contexts).
JSON-in-script blocks now escape U+2028/U+2029 line separators."
```

---

## Task 26: `successResponse` no mutation; cookie config env-driven; dedup maxDuration (Low)

**Files:**
- Modify: `src/lib/response.ts:7-12`
- Modify: `src/config.ts` (drive cookie.secure from env; remove unused `test.maxDuration` or wire it)
- Modify: `src/routes/result.ts:15` (use `config.test.maxDuration` instead of local constant)

- [ ] **Step 1: Fix `successResponse` to not mutate**

In `src/lib/response.ts`:
```ts
	static successResponse(data: Record<string, any> = {}): { content: Record<string, any> } {
		return {
			content: { ...data, success: 1 },
		};
	}
```

- [ ] **Step 2: Wire `config.test.maxDuration`**

In `src/routes/result.ts`, remove line 15 (`const MAX_TEST_DURATION = ...`) and replace references with `config.test.maxDuration`.

- [ ] **Step 3: Typecheck + test**

Run: `npx tsc --noEmit && npx vitest run`
Expected: pass.

- [ ] **Step 4: Commit**

```bash
git add src/lib/response.ts src/routes/result.ts
git commit -m "fix(low): successResponse no longer mutates its argument; dedup maxDuration"
```

---

## Task 27: Final typecheck + full test run

- [ ] **Step 1: Full typecheck**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 2: Full test suite**

Run: `npx vitest run`
Expected: all tests pass.

- [ ] **Step 3: Review the diff**

Run: `git diff main...HEAD --stat`
Review the summary of all changes.

- [ ] **Step 4: Final commit (if any cleanup needed)**

---

## Self-Review Notes

**Spec coverage:** All 4 Critical, ~10 High, ~11 Medium, ~8 Low issues from the 4 review reports are addressed by Tasks 1-27. The review reports are in `review/{security,crypto,logic,quality}.md`.

**Type consistency:** `hkdfDerive` returns `Promise<Uint8Array>` — consumed by `config.ts` as `aesKey`/`hmacKey`, passed to `encryptObject(obj, aesKey: Uint8Array)`, `decryptString(str, aesKey: Uint8Array)`, `signSessionId(id, hmacKey: Uint8Array)`, `verifySessionId(val, hmacKey: Uint8Array)`. `getConfig` is async. `computePayloadHash` is async. `updateState` becomes async. `constantTimeEqual` is sync. `safeParseInt` is sync. `isSafeCallbackUrl` is sync. `callDoJson` is async.

**Dependencies:** Task 8 (HKDF) is the most invasive — it changes signatures across config, encryption, session, routes, and DO. Execute it after Task 7 (AES-GCM) so the algorithm and key separation land together. Task 9 (payloadHash) depends on Task 8 (async config). Task 14 (constant-time) depends on Task 8 (crypto-utils module). Task 16 (shared callDoJson) depends on Task 2 (which touched result.ts).
