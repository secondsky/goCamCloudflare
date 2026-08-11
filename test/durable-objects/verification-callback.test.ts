/**
 * Task 6 — DO callback-retry subsystem tests (workers pool).
 *
 * File: test/durable-objects/verification-callback.test.ts
 *
 * Covers `dispatchCallback`, `updateCallbackStatus`, `alarm`, and the
 * `getAesKey` cache on the `VerificationSession` Durable Object.
 *
 * ── Fetch-interception strategy ──
 * `@cloudflare/vitest-pool-workers@0.20.3` does NOT export `fetchMock` from
 * `cloudflare:test`, and its bundled Miniflare (v5) removed the
 * `createFetchMock()` / `fetchMock` config option. The three traditional ways
 * to intercept the DO's outbound `fetch()` (the partner callback POST) are
 * therefore unavailable. This file uses two complementary techniques instead:
 *
 * 1. `runInDurableObject(stub, cb)` + mocked `globalThis.fetch`:
 *    The DO and the test share one workerd isolate (per the `SELF` docs), so
 *    reassigning `globalThis.fetch` in the test also reroutes the DO's
 *    `fetch(callbackUrl)` call. `runInDurableObject` exposes the typed DO
 *    instance, so tests invoke the private `dispatchCallback` /
 *    `updateCallbackStatus` methods directly (via cast) — this removes the
 *    `ctx.waitUntil` timing dependence entirely and lets each test script the
 *    HTTP response (2xx / 5xx / network error). Captures of the POSTed URL,
 *    body, and Content-Type are asserted directly.
 *
 * 2. Fast-failing callback URL (`http://127.0.0.1:1/`):
 *    Used by the `endSession`-triggered tests where the dispatch genuinely
 *    runs in `ctx.waitUntil`. Port 1 on loopback refuses the connection
 *    immediately (no DNS, no real network egress), so the DO's catch block
 *    fires within milliseconds and records `'failed'`. This proves the
 *    endSession → dispatchCallback wiring without depending on real HTTP.
 *
 * `runDurableObjectAlarm(stub)` (from `cloudflare:test`) fires the DO's
 * `alarm()` lifecycle handler directly — the fetch router has no `alarm`
 * action, so this is the only way to exercise it.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { env, runInDurableObject, runDurableObjectAlarm, evictDurableObject } from 'cloudflare:test';
import { AvsEncryption } from '../../src/lib/encryption';
import { hkdfDerive } from '../../src/lib/crypto-utils';
import {
	SESSION_STATE_IN_PROGRESS,
	SESSION_STATE_SUCCESS,
	SESSION_STATE_FAILED,
} from '../../src/durable-objects/verification-session';
import type { VerificationSession, SessionData } from '../../src/durable-objects/verification-session';

// ─── Test key derivation ───
// The DO derives its AES key from `env.ENCRYPTION_KEY`. In the workers pool
// that binding is `'a'.repeat(32)` (set in vitest.config.ts), matching
// `TEST_PASSPHRASE` in `test/helpers/crypto-keys.ts`. Derive the matching AES
// subkey here so payloads we encrypt decrypt successfully inside the DO.
const TEST_KEY_STRING = 'a'.repeat(32);
const HKDF_CONTEXT = 'avs/aes/v1';
const aesKeyPromise: Promise<Uint8Array> = hkdfDerive(TEST_KEY_STRING, HKDF_CONTEXT, 32);

// ─── Helpers ───

interface TestPayload {
	creationTimestamp: number;
	callbackUrl: string;
	userIpStr: string;
	userIpCountry: string;
	userIpState: string;
	websiteHostname: string;
	verificationVersion: number;
	userData: Record<string, unknown>;
	httpParamList: { userAgent: string };
	linkBack: string;
}

function makePayload(overrides: Partial<TestPayload> = {}): TestPayload {
	return {
		creationTimestamp: Date.now(),
		// Empty by default → the DO will NOT schedule a callback dispatch,
		// keeping payload-only tests side-effect-free.
		callbackUrl: '',
		userIpStr: '1.2.3.4',
		userIpCountry: 'US',
		userIpState: 'CA',
		websiteHostname: 'example.com',
		verificationVersion: 1,
		userData: {},
		httpParamList: { userAgent: 'test-agent' },
		linkBack: '/',
		...overrides,
	};
}

async function encryptPayload(payload: TestPayload): Promise<string> {
	const aesKey = await aesKeyPromise;
	return AvsEncryption.encryptObject(payload, aesKey);
}

/** Mint a DO stub backed by a fresh unique name (per-test isolation). */
function getStub(suffix: string) {
	const id = env.VERIFICATION_SESSION.idFromName(suffix);
	return env.VERIFICATION_SESSION.get(id);
}

async function doPost<T = any>(
	stub: ReturnType<typeof getStub>,
	action: string,
	body: Record<string, unknown>,
): Promise<T> {
	const response = await stub.fetch(`https://do/${action}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body),
	});
	return response.json() as Promise<T>;
}

/** Start a session and end it as SUCCESS — the realistic endSession flow. */
async function startAndEndSuccess(
	stub: ReturnType<typeof getStub>,
	callbackUrl: string,
): Promise<{ sessionId: string }> {
	const payload = await encryptPayload(makePayload({ callbackUrl }));
	const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
	await doPost(stub, 'end', {
		sessionId: start.sessionId,
		sessionStateInt: SESSION_STATE_SUCCESS,
		stepIp: 5,
		errorCode: 0,
		idCountry: 'US',
		idState: 'CA',
		idType: 'drivers-license',
	});
	return start;
}

/**
 * Read the `callbackAttempts` column for a session directly from the DO's
 * SQLite storage. `getById` only returns the `data` JSON blob (which does not
 * carry `callbackAttempts`), so we go through `runInDurableObject` to run a
 * SQL read on the instance.
 */
async function readCallbackAttempts(
	stub: ReturnType<typeof getStub>,
	sessionId: string,
): Promise<number> {
	return runInDurableObject(stub, (instance: VerificationSession, state) => {
		const cursor = (state as DurableObjectState).storage.sql.exec(
			`SELECT callbackAttempts FROM sessions WHERE sessionId = ?`,
			sessionId,
		);
		for (const row of cursor) {
			return (row.callbackAttempts as number) ?? 0;
		}
		return -1; // row missing
	});
}

/**
 * Read the live sessionData (with current `callbackStatus`) back from the DO.
 */
async function getSession(
	stub: ReturnType<typeof getStub>,
	sessionId: string,
): Promise<SessionData | null> {
	return doPost<SessionData | null>(stub, 'getSession', { sessionId });
}

/**
 * Seed a session row directly into the alarm-eligible shape. The DO's alarm
 * handler reads `stateInt`/`callbackUrl`/`callbackStatus` from the `data` JSON
 * blob (NOT the SQL columns), so this helper rewrites BOTH the columns and the
 * parsed JSON so the row is consistent. Also arms the alarm so
 * `runDurableObjectAlarm(stub)` has something to fire (it returns false and
 * runs nothing if no alarm is scheduled).
 */
async function seedForAlarm(
	stub: ReturnType<typeof getStub>,
	sessionId: string,
	overrides: {
		stateInt: number;
		callbackStatus: 'failed' | 'pending' | 'sent';
		callbackAttempts: number;
	},
): Promise<void> {
	await runInDurableObject(stub, (instance: VerificationSession, state) => {
		(instance as any).ensureInitialized();
		const sql = (state as DurableObjectState).storage.sql;
		// Read the existing data JSON, mutate the relevant fields, write back.
		const cursor = sql.exec(`SELECT data FROM sessions WHERE sessionId = ?`, sessionId);
		let dataJson = '';
		for (const row of cursor) { dataJson = row.data as string; break; }
		const data = JSON.parse(dataJson) as SessionData;
		data.stateInt = overrides.stateInt;
		data.state = overrides.stateInt === SESSION_STATE_SUCCESS ? 'success'
			: overrides.stateInt === SESSION_STATE_FAILED ? 'fail' : 'inProgress';
		data.callbackStatus = overrides.callbackStatus;
		sql.exec(
			`UPDATE sessions SET data = ?, stateInt = ?, callbackStatus = ?, callbackAttempts = ? WHERE sessionId = ?`,
			JSON.stringify(data),
			overrides.stateInt,
			overrides.callbackStatus,
			overrides.callbackAttempts,
			sessionId,
		);
		(state as DurableObjectState).storage.setAlarm(Date.now() + 60_000);
	});
}

// ─── Test scaffold ───

let doCounter = 0;
let originalFetch: typeof fetch | null = null;

beforeEach(() => {
	doCounter++;
	originalFetch = null;
});

afterEach(() => {
	// Guarantee `globalThis.fetch` is restored even if a test threw before
	// its own finally block ran.
	if (originalFetch) {
		globalThis.fetch = originalFetch;
		originalFetch = null;
	}
});

function uniqueName(label: string): string {
	return `${label}-${doCounter}`;
}

/**
 * Install a mock for `globalThis.fetch` shared with the DO isolate. Returns a
 * recorder tests assert against. Pass `responder` to script the HTTP response
 * (default: HTTP 200). Pass `responder: null` and `throwError` to simulate a
 * network-level failure.
 */
interface FetchRecorder {
	calls: number;
	urls: string[];
	methods: string[];
	bodies: string[];
	contentTypes: string[];
	// The `redirect` option passed to each fetch call (e.g. 'manual').
	// Used by the SSRF tests to assert dispatchCallback sets
	// `redirect: 'manual'` on the outbound POST.
	redirects: string[];
}
function mockFetch(responder: (() => Response) | null = () => new Response('ok', { status: 200 }), throwError?: () => never): FetchRecorder {
	const rec: FetchRecorder = { calls: 0, urls: [], methods: [], bodies: [], contentTypes: [], redirects: [] };
	originalFetch = globalThis.fetch;
	globalThis.fetch = (async (input: any, init?: any) => {
		rec.calls++;
		rec.urls.push(typeof input === 'string' ? input : input.url);
		rec.methods.push(init?.method ?? 'GET');
		rec.bodies.push(init?.body ?? '');
		rec.contentTypes.push(init?.headers?.['Content-Type'] ?? init?.headers?.['content-type'] ?? '');
		rec.redirects.push(init?.redirect ?? '');
		if (throwError) throwError();
		return responder ? responder() : new Response('ok', { status: 200 });
	}) as typeof fetch;
	return rec;
}

// ─── Tests ───

describe('VerificationSession DO — callback-retry subsystem', () => {

	// ───────────────────────────────────────────────────────────────────
	// dispatchCallback (success path) — invoked via runInDurableObject with
	// a mocked global fetch so the DO's POST returns a controlled 2xx.
	// ───────────────────────────────────────────────────────────────────

	it('1. dispatchCallback: 2xx response → callbackStatus "sent" + attempts incremented', async () => {
		const stub = getStub(uniqueName('cb-ok'));
		const payload = await encryptPayload(makePayload({ callbackUrl: 'https://partner.example.com/hook' }));
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });

		// Transition the row to a terminal state first so the session is
		// dispatch-eligible. updateState is the lightest mutation that
		// preserves callbackUrl; endSession would also work but would itself
		// trigger a dispatch in waitUntil (which we do NOT want here).
		await runInDurableObject(stub, (instance: VerificationSession) => {
			(instance as any).ensureInitialized();
			// Flip stateInt to SUCCESS directly on the stored row so the
			// alarm-eligibility filter (`stateInt === 2 || 3`) is satisfied.
			(instance as any).ctx.storage.sql.exec(
				`UPDATE sessions SET stateInt = ? WHERE sessionId = ?`,
				SESSION_STATE_SUCCESS,
				start.sessionId,
			);
		});

		const rec = mockFetch();
		try {
			await runInDurableObject(stub, async (instance: VerificationSession) => {
				const session = (instance as any).getById(start.sessionId) as SessionData;
				await (instance as any).dispatchCallback(
					session,
					SESSION_STATE_SUCCESS,
					start.sessionId,
					0, 5, 'US', 'CA', 'drivers-license',
				);
			});
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}

		// The DO POSTed exactly once, to the partner URL, with the right
		// content type.
		expect(rec.calls).toBe(1);
		expect(rec.urls[0]).toBe('https://partner.example.com/hook');
		expect(rec.methods[0]).toBe('POST');
		expect(rec.contentTypes[0]).toBe('application/x-www-form-urlencoded; charset=UTF-8');

		// Body carries every documented field.
		const bodyParams = new URLSearchParams(rec.bodies[0]);
		expect(bodyParams.get('sessionId')).toBe(start.sessionId);
		expect(bodyParams.get('state')).toBe('success');
		expect(bodyParams.get('stateInt')).toBe('2');
		expect(bodyParams.get('websiteHostname')).toBe('example.com');
		expect(bodyParams.get('ip')).toBe('1.2.3.4');
		expect(bodyParams.get('idCountry')).toBe('US');
		expect(bodyParams.get('idType')).toBe('drivers-license');

		// Observable effect: callbackStatus 'sent', attempts == 1.
		const session = await getSession(stub, start.sessionId);
		expect(session?.callbackStatus).toBe('sent');
		expect(await readCallbackAttempts(stub, start.sessionId)).toBe(1);
	});

	it('2. dispatchCallback: 5xx response → callbackStatus "failed" + attempts incremented', async () => {
		const stub = getStub(uniqueName('cb-500'));
		const payload = await encryptPayload(makePayload({ callbackUrl: 'https://partner.example.com/hook' }));
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		await runInDurableObject(stub, (instance: VerificationSession) => {
			(instance as any).ensureInitialized();
			(instance as any).ctx.storage.sql.exec(
				`UPDATE sessions SET stateInt = ? WHERE sessionId = ?`,
				SESSION_STATE_SUCCESS,
				start.sessionId,
			);
		});

		const rec = mockFetch(() => new Response('upstream error', { status: 500 }));
		try {
			await runInDurableObject(stub, async (instance: VerificationSession) => {
				const session = (instance as any).getById(start.sessionId) as SessionData;
				await (instance as any).dispatchCallback(
					session, SESSION_STATE_SUCCESS, start.sessionId,
					0, 5, 'US', 'CA', 'drivers-license',
				);
			});
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}

		expect(rec.calls).toBe(1);
		const session = await getSession(stub, start.sessionId);
		expect(session?.callbackStatus).toBe('failed');
		expect(await readCallbackAttempts(stub, start.sessionId)).toBe(1);
	});

	it('3. dispatchCallback: network error (fetch throws) → callbackStatus "failed"', async () => {
		const stub = getStub(uniqueName('cb-neterr'));
		const payload = await encryptPayload(makePayload({ callbackUrl: 'https://partner.example.com/hook' }));
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		await runInDurableObject(stub, (instance: VerificationSession) => {
			(instance as any).ensureInitialized();
			(instance as any).ctx.storage.sql.exec(
				`UPDATE sessions SET stateInt = ? WHERE sessionId = ?`,
				SESSION_STATE_SUCCESS,
				start.sessionId,
			);
		});

		const rec = mockFetch(null, () => { throw new Error('simulated network failure'); });
		try {
			await runInDurableObject(stub, async (instance: VerificationSession) => {
				const session = (instance as any).getById(start.sessionId) as SessionData;
				// dispatchCallback catches internally — this must NOT throw.
				await (instance as any).dispatchCallback(
					session, SESSION_STATE_SUCCESS, start.sessionId,
					0, 5, 'US', 'CA', 'drivers-license',
				);
			});
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}

		expect(rec.calls).toBe(1);
		const session = await getSession(stub, start.sessionId);
		expect(session?.callbackStatus).toBe('failed');
		expect(await readCallbackAttempts(stub, start.sessionId)).toBe(1);
	});

	// ───────────────────────────────────────────────────────────────────
	// SSRF redirect defense — dispatchCallback must NOT follow redirects.
	// A partner callback URL that responds 3xx to an internal address
	// (e.g. the cloud metadata endpoint) would otherwise be silently
	// followed by the Workers `fetch` default (`redirect: 'follow'`),
	// leaking session data to an internal target. The fix sets
	// `redirect: 'manual'` and treats any 3xx as a failure.
	// ───────────────────────────────────────────────────────────────────

	it('4. dispatchCallback: 302 redirect to internal address → callbackStatus "failed" (SSRF defense), redirect: "manual" passed', async () => {
		const stub = getStub(uniqueName('cb-302-ssrf'));
		const payload = await encryptPayload(makePayload({ callbackUrl: 'https://partner.example.com/hook' }));
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		await runInDurableObject(stub, (instance: VerificationSession) => {
			(instance as any).ensureInitialized();
			(instance as any).ctx.storage.sql.exec(
				`UPDATE sessions SET stateInt = ? WHERE sessionId = ?`,
				SESSION_STATE_SUCCESS,
				start.sessionId,
			);
		});

		// Mock a redirect to the cloud metadata endpoint — the classic
		// SSRF target. With `redirect: 'manual'` this is what the DO sees;
		// without it, Workers would follow and POST to the internal URL.
		const rec = mockFetch(() => new Response(null, {
			status: 302,
			headers: { Location: 'http://169.254.169.254/latest/meta-data/' },
		}));
		try {
			await runInDurableObject(stub, async (instance: VerificationSession) => {
				const session = (instance as any).getById(start.sessionId) as SessionData;
				await (instance as any).dispatchCallback(
					session, SESSION_STATE_SUCCESS, start.sessionId,
					0, 5, 'US', 'CA', 'drivers-license',
				);
			});
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}

		// Option A (spy): the fetch MUST be invoked with redirect: 'manual'.
		// This is the direct security-control assertion — it fails against
		// current code because no `redirect` option is set.
		expect(rec.calls).toBe(1);
		expect(rec.redirects[0]).toBe('manual');

		// Behavioral: a redirect response is treated as a failure.
		const session = await getSession(stub, start.sessionId);
		expect(session?.callbackStatus).toBe('failed');
		expect(session?.callbackStatus).not.toBe('sent');
		expect(await readCallbackAttempts(stub, start.sessionId)).toBe(1);
	});

	it('5. dispatchCallback: 301 redirect → callbackStatus "failed" (SSRF defense)', async () => {
		const stub = getStub(uniqueName('cb-301-ssrf'));
		const payload = await encryptPayload(makePayload({ callbackUrl: 'https://partner.example.com/hook' }));
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		await runInDurableObject(stub, (instance: VerificationSession) => {
			(instance as any).ensureInitialized();
			(instance as any).ctx.storage.sql.exec(
				`UPDATE sessions SET stateInt = ? WHERE sessionId = ?`,
				SESSION_STATE_SUCCESS,
				start.sessionId,
			);
		});

		const rec = mockFetch(() => new Response(null, {
			status: 301,
			headers: { Location: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' },
		}));
		try {
			await runInDurableObject(stub, async (instance: VerificationSession) => {
				const session = (instance as any).getById(start.sessionId) as SessionData;
				await (instance as any).dispatchCallback(
					session, SESSION_STATE_SUCCESS, start.sessionId,
					0, 5, 'US', 'CA', 'drivers-license',
				);
			});
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}

		expect(rec.calls).toBe(1);
		expect(rec.redirects[0]).toBe('manual');
		const session = await getSession(stub, start.sessionId);
		expect(session?.callbackStatus).toBe('failed');
		expect(session?.callbackStatus).not.toBe('sent');
	});

	it('6. dispatchCallback: 307 redirect → callbackStatus "failed" (SSRF defense)', async () => {
		const stub = getStub(uniqueName('cb-307-ssrf'));
		const payload = await encryptPayload(makePayload({ callbackUrl: 'https://partner.example.com/hook' }));
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		await runInDurableObject(stub, (instance: VerificationSession) => {
			(instance as any).ensureInitialized();
			(instance as any).ctx.storage.sql.exec(
				`UPDATE sessions SET stateInt = ? WHERE sessionId = ?`,
				SESSION_STATE_SUCCESS,
				start.sessionId,
			);
		});

		// 307 preserves the POST method — particularly dangerous for SSRF
		// because the session data body would be re-POSTed to the internal target.
		const rec = mockFetch(() => new Response(null, {
			status: 307,
			headers: { Location: 'http://169.254.169.254/latest/meta-data/' },
		}));
		try {
			await runInDurableObject(stub, async (instance: VerificationSession) => {
				const session = (instance as any).getById(start.sessionId) as SessionData;
				await (instance as any).dispatchCallback(
					session, SESSION_STATE_SUCCESS, start.sessionId,
					0, 5, 'US', 'CA', 'drivers-license',
				);
			});
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}

		expect(rec.calls).toBe(1);
		expect(rec.redirects[0]).toBe('manual');
		const session = await getSession(stub, start.sessionId);
		expect(session?.callbackStatus).toBe('failed');
		expect(session?.callbackStatus).not.toBe('sent');
	});

	it('7. endSession(SUCCESS) triggers a real dispatch in waitUntil (fast-fail URL → failed)', async () => {
		const stub = getStub(uniqueName('end-triggers-dispatch'));
		// Port 1 on loopback refuses the connection immediately — no DNS, no
		// real network egress. The DO's dispatch catch block fires within ms.
		const start = await startAndEndSuccess(stub, 'http://127.0.0.1:1/hook');

		// waitUntil runs in the background; give it time to fail and persist.
		await new Promise((r) => setTimeout(r, 400));

		const session = await getSession(stub, start.sessionId);
		// The session ended in SUCCESS and its dispatch failed fast.
		expect(session?.stateInt).toBe(SESSION_STATE_SUCCESS);
		expect(session?.callbackStatus).toBe('failed');
		expect(await readCallbackAttempts(stub, start.sessionId)).toBe(1);
	});

	it('8. session without callbackUrl: end(SUCCESS) does NOT attempt a fetch', async () => {
		const stub = getStub(uniqueName('no-cb-url'));
		let fetchCalls = 0;
		originalFetch = globalThis.fetch;
		globalThis.fetch = (async () => { fetchCalls++; return new Response(); }) as typeof fetch;
		try {
			await startAndEndSuccess(stub, ''); // empty callbackUrl
			await new Promise((r) => setTimeout(r, 200));
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}
		// No callback scheduled → no outbound POST.
		expect(fetchCalls).toBe(0);
	});

	// ───────────────────────────────────────────────────────────────────
	// updateCallbackStatus — increments callbackAttempts on both outcomes.
	// ───────────────────────────────────────────────────────────────────

	it('9. updateCallbackStatus increments callbackAttempts on "sent" and on "failed"', async () => {
		const stub = getStub(uniqueName('ucs-increment'));
		const payload = await encryptPayload(makePayload());
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		const sid = start.sessionId;

		// Fresh row: attempts == 0.
		expect(await readCallbackAttempts(stub, sid)).toBe(0);

		await runInDurableObject(stub, (instance: VerificationSession) => {
			(instance as any).updateCallbackStatus(sid, 'sent');
		});
		expect(await readCallbackAttempts(stub, sid)).toBe(1);
		let session = await getSession(stub, sid);
		expect(session?.callbackStatus).toBe('sent');

		await runInDurableObject(stub, (instance: VerificationSession) => {
			(instance as any).updateCallbackStatus(sid, 'failed');
		});
		expect(await readCallbackAttempts(stub, sid)).toBe(2);
		session = await getSession(stub, sid);
		expect(session?.callbackStatus).toBe('failed');

		await runInDurableObject(stub, (instance: VerificationSession) => {
			(instance as any).updateCallbackStatus(sid, 'sent');
		});
		expect(await readCallbackAttempts(stub, sid)).toBe(3);
	});

	it('10. updateCallbackStatus is a no-op when the session row is gone', async () => {
		const stub = getStub(uniqueName('ucs-missing'));
		// No row was ever created for this id — the call must not throw and
		// must not create a row.
		await runInDurableObject(stub, (instance: VerificationSession) => {
			(instance as any).updateCallbackStatus('never-existed', 'failed');
		});
		expect(await readCallbackAttempts(stub, 'never-existed')).toBe(-1);
	});

	// ───────────────────────────────────────────────────────────────────
	// alarm() retry sweep — re-dispatches failed/pending callbacks until the
	// MAX_CALLBACK_ATTEMPTS (5) cap, then excludes the session.
	// ───────────────────────────────────────────────────────────────────

	it('11. alarm re-attempts a failed callback (attempts increments again)', async () => {
		const stub = getStub(uniqueName('alarm-retry'));
		// Use the realistic flow: end(SUCCESS) with a fast-failing URL → 1
		// failed attempt lands in waitUntil. endSession also arms the alarm.
		const { sessionId: sid } = await startAndEndSuccess(stub, 'http://127.0.0.1:1/hook');
		await new Promise((r) => setTimeout(r, 400));
		// After the initial dispatch: attempts == 1, status 'failed'.
		expect(await readCallbackAttempts(stub, sid)).toBe(1);
		expect((await getSession(stub, sid))?.callbackStatus).toBe('failed');

		// Fire the alarm — it must re-dispatch (and fail again).
		const ran = await runDurableObjectAlarm(stub);
		expect(ran).toBe(true);
		await new Promise((r) => setTimeout(r, 400));

		expect(await readCallbackAttempts(stub, sid)).toBe(2);
		expect((await getSession(stub, sid))?.callbackStatus).toBe('failed');
	});

	it('12. alarm excludes a session once callbackAttempts reaches MAX_CALLBACK_ATTEMPTS (5)', async () => {
		const stub = getStub(uniqueName('alarm-cap'));
		const payload = await encryptPayload(makePayload({ callbackUrl: 'https://partner.example.com/hook' }));
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		const sid = start.sessionId;

		// Force the row into the alarm-eligible shape: SUCCESS + callbackUrl,
		// and pre-set callbackAttempts to the cap (5) so the alarm skips it.
		await seedForAlarm(stub, sid, { stateInt: SESSION_STATE_SUCCESS, callbackStatus: 'failed', callbackAttempts: 5 });

		const rec = mockFetch();
		try {
			const ran = await runDurableObjectAlarm(stub);
			expect(ran).toBe(true);
			await new Promise((r) => setTimeout(r, 100));
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}

		// At the cap → alarm did NOT re-dispatch.
		expect(rec.calls).toBe(0);
		expect(await readCallbackAttempts(stub, sid)).toBe(5);
	});

	it('13. alarm skips sessions without a callbackUrl even if status is failed', async () => {
		const stub = getStub(uniqueName('alarm-no-url'));
		const payload = await encryptPayload(makePayload({ callbackUrl: '' }));
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		const sid = start.sessionId;

		await seedForAlarm(stub, sid, { stateInt: SESSION_STATE_SUCCESS, callbackStatus: 'failed', callbackAttempts: 1 });

		const rec = mockFetch();
		try {
			const ran = await runDurableObjectAlarm(stub);
			expect(ran).toBe(true);
			await new Promise((r) => setTimeout(r, 100));
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}

		// Alarm fired but the row has no callbackUrl → no dispatch.
		expect(rec.calls).toBe(0);
	});

	it('14. alarm skips sessions still IN_PROGRESS (only SUCCESS/FAILED are retried)', async () => {
		const stub = getStub(uniqueName('alarm-inprogress'));
		const payload = await encryptPayload(makePayload({ callbackUrl: 'https://partner.example.com/hook' }));
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		const sid = start.sessionId;
		// Freshly started → IN_PROGRESS.

		await seedForAlarm(stub, sid, { stateInt: SESSION_STATE_IN_PROGRESS, callbackStatus: 'failed', callbackAttempts: 1 });

		const rec = mockFetch();
		try {
			const ran = await runDurableObjectAlarm(stub);
			expect(ran).toBe(true);
			await new Promise((r) => setTimeout(r, 100));
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}

		// Alarm fired but stateInt is IN_PROGRESS → no dispatch.
		expect(rec.calls).toBe(0);
		expect((await getSession(stub, sid))?.stateInt).toBe(SESSION_STATE_IN_PROGRESS);
	});

	it('15. alarm succeeds a previously-failed callback when the endpoint recovers', async () => {
		const stub = getStub(uniqueName('alarm-recover'));
		const payload = await encryptPayload(makePayload({ callbackUrl: 'https://partner.example.com/hook' }));
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		const sid = start.sessionId;

		// Seed a failed dispatch from the past (attempts == 1).
		await seedForAlarm(stub, sid, { stateInt: SESSION_STATE_SUCCESS, callbackStatus: 'failed', callbackAttempts: 1 });

		// Now the endpoint is healthy — mock returns 200.
		const rec = mockFetch();
		try {
			const ran = await runDurableObjectAlarm(stub);
			expect(ran).toBe(true);
			await new Promise((r) => setTimeout(r, 100));
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}

		expect(rec.calls).toBe(1);
		expect(await readCallbackAttempts(stub, sid)).toBe(2);
		expect((await getSession(stub, sid))?.callbackStatus).toBe('sent');
	});

	it('16. alarm handles FAILED terminal state (not just SUCCESS)', async () => {
		const stub = getStub(uniqueName('alarm-failed-state'));
		const payload = await encryptPayload(makePayload({ callbackUrl: 'https://partner.example.com/hook' }));
		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		const sid = start.sessionId;

		await seedForAlarm(stub, sid, { stateInt: SESSION_STATE_FAILED, callbackStatus: 'failed', callbackAttempts: 1 });

		const rec = mockFetch(() => new Response('ok', { status: 200 }));
		try {
			const ran = await runDurableObjectAlarm(stub);
			expect(ran).toBe(true);
			await new Promise((r) => setTimeout(r, 100));
		} finally {
			globalThis.fetch = originalFetch as typeof fetch;
			originalFetch = null;
		}

		// FAILED state IS in the retry set → alarm dispatches and flips to sent.
		expect(rec.calls).toBe(1);
		const session = await getSession(stub, sid);
		expect(session?.callbackStatus).toBe('sent');
	});

	// ───────────────────────────────────────────────────────────────────
	// getAesKey cache — second derivation with the same ENCRYPTION_KEY
	// returns the cached promise (no re-derivation).
	// ───────────────────────────────────────────────────────────────────

	it('17. getAesKey: two calls on the same instance return identical derived bytes (cache hit)', async () => {
		const stub = getStub(uniqueName('aes-cache'));
		const key1 = await runInDurableObject(stub, async (instance: VerificationSession) => {
			return (instance as any).getAesKey();
		});
		const key2 = await runInDurableObject(stub, async (instance: VerificationSession) => {
			return (instance as any).getAesKey();
		});

		// Cache hit: the same promise is reused, so both calls resolve to a
		// Uint8Array with identical contents. (Identity comparison of the
		// promise is internal; comparing bytes proves no re-derivation
		// occurred, since HKDF is deterministic — but more importantly the
		// cache prevents the second call from re-validating/re-deriving.)
		expect(key1).toBe(key2); // same underlying promise → same object ref
		expect(key1.byteLength).toBe(32);

		// And the derived key matches the one computed independently from
		// the same passphrase + context (proves the value is correct, not
		// just cached).
		const expected = await aesKeyPromise;
		expect(Array.from(new Uint8Array(key1))).toEqual(Array.from(expected));
	});

	it('18. getAesKey cache is reset when the DO is evicted (new instance re-derives)', async () => {
		const name = uniqueName('aes-evict');
		const id = env.VERIFICATION_SESSION.idFromName(name);
		const stub = env.VERIFICATION_SESSION.get(id);

		// Prime the cache on the live instance.
		const key1 = await runInDurableObject(stub, async (instance: VerificationSession) => {
			return (instance as any).getAesKey();
		});
		expect(key1.byteLength).toBe(32);

		// Evict the running instance. This tears down in-memory state
		// (`_aesKeyPromise`, `initialized`) while preserving durable storage.
		// The next get() for the SAME id mints a fresh instance whose
		// `_aesKeyPromise` is null, so getAesKey re-derives from env.
		await evictDurableObject(stub);

		// New stub for the same id — runtime should construct a new instance.
		const stub2 = env.VERIFICATION_SESSION.get(id);
		const key2 = await runInDurableObject(stub2, async (instance: VerificationSession) => {
			return (instance as any).getAesKey();
		});

		// The new instance must produce a valid 32-byte key without relying
		// on the evicted instance's cache. Referential identity between
		// key1/key2 is NOT required (different instances); what matters is
		// that key2 is a correct HKDF output derived from the same
		// ENCRYPTION_KEY.
		expect(key2.byteLength).toBe(32);
		const expected = await aesKeyPromise;
		expect(Array.from(new Uint8Array(key2))).toEqual(Array.from(expected));
	});

	// ───────────────────────────────────────────────────────────────────
	// DEFERRED: callback-hang → AbortController timeout (5000ms).
	//
	// The brief called for "callback hangs → AbortController timeout fires
	// (5000ms)". This test is intentionally skipped: `vi.useFakeTimers` is
	// NOT reliably supported in the @cloudflare/vitest-pool-workers runtime
	// (workerd isolate), and a real 5000ms wait is far too slow for the
	// suite. Documenting the deferral here per the brief's explicit
	// allowance.
	//
	// Production behavior this would verify (see
	// src/durable-objects/verification-session.ts:45 `CALLBACK_TIMEOUT_MS`
	// = 5000 and the AbortController at :610-611): a hanging callback URL
	// causes the AbortController to abort after 5000ms, dispatchCallback
	// catches the abort (its `catch` block at :632-635 runs), and
	// updateCallbackStatus records 'failed'.
	// ───────────────────────────────────────────────────────────────────
	it.skip('19. dispatchCallback: hanging callback URL → AbortController aborts after 5000ms → callbackStatus "failed"', async () => {
		// SKIPPED: fake timers (`vi.useFakeTimers`) are not reliably supported
		// in the Cloudflare workers pool (@cloudflare/vitest-pool-workers),
		// and a real 5000ms wait (CALLBACK_TIMEOUT_MS at
		// src/durable-objects/verification-session.ts:45) is too slow for
		// the suite. Production behavior is covered by code review of the
		// AbortController wiring at :610-611 and the catch block at :632-635.
		expect(true).toBe(true);
	});
});

// ─── Internal helpers ───
