import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request } from '@cloudflare/workers-types';
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

// ─── handleResultRoutes direct handler tests ───
//
// Mirrors the pattern in test/routes/token.test.ts: getConfig caches its result
// at module scope keyed by ENCRYPTION_KEY, so we vi.resetModules() before each
// test and re-import the handler fresh. The DO stub's .fetch dispatches on the
// last path segment (the "action") and returns scripted Response objects whose
// JSON bodies match what callDoJson expects.

// getConfig caches its result at module scope keyed by ENCRYPTION_KEY. Reset
// modules before each test so every test re-derives config from the mock env.
beforeEach(() => {
	vi.resetModules();
});

// Mint a valid signed avs-session cookie value and return the full
// `avs-session=<value>` string suitable for the Cookie header.
// Uses the test HMAC key (derived from TEST_PASSPHRASE 'a'.repeat(32)) so the
// production code's getSessionContextFromRequest accepts it.
async function makeSessionCookieHeader(
	payloadHash: string,
	requestSessionId: string,
): Promise<string> {
	const { createSessionCookie } = await import('../../src/middleware/session');
	const { getTestKeys } = await import('../helpers/crypto-keys');
	const { hmacKey } = await getTestKeys();
	const setCookie = await createSessionCookie(payloadHash, requestSessionId, hmacKey);
	// createSessionCookie returns "avs-session=<signed>; Path=/; HttpOnly; ..."
	// For the Cookie request header we only want the "name=value" segment.
	return setCookie.split(';')[0];
}

// Build a mock Env whose VERIFICATION_SESSION DO stub has a scripted .fetch.
// `responses` is a map of action (last path segment) -> Response body object
// (or an Error to throw, or a { __status, ...body } to set a non-200 status).
// callDoJson throws when the body has an `error` field or status is non-OK.
function makeEnv(responses: Record<string, any> = {}): { env: any; fetchMock: any } {
	const fetchMock = vi.fn(async (req: Request) => {
		const url = new URL(req.url);
		const action = url.pathname.split('/').filter(Boolean).pop() || '';
		const scripted = responses[action];
		if (scripted instanceof Error) throw scripted;
		if (scripted === undefined) {
			// Default: empty 200 OK with no error field.
			return new Response(JSON.stringify({ success: true }), { status: 200 });
		}
		const status =
			scripted && typeof scripted === 'object' && scripted.__status ? scripted.__status : 200;
		return new Response(JSON.stringify(scripted), { status });
	});

	const stub = { fetch: fetchMock };
	return {
		env: {
			VERIFICATION_SESSION: {
				idFromName: vi.fn().mockReturnValue('do-id-123'),
				get: vi.fn().mockReturnValue(stub),
			},
			ANALYTICS: {} as any,
			ASSETS: {} as any,
			ENCRYPTION_KEY: 'a'.repeat(32),
			ENCRYPTION_ALGORITHM: 'AES-GCM',
			ENABLE_FRONTEND_DEBUG: 'false',
		},
		fetchMock,
	};
}

// Import dynamically after vi.resetModules() so getConfig is fresh per test.
async function importHandler() {
	const mod = await import('../../src/routes/result');
	return mod.handleResultRoutes;
}

// Build a JSON POST request to a given pathname.
function jsonRequest(pathname: string, body: unknown, headers: Record<string, string> = {}): Request {
	return new Request(`https://x${pathname}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...headers },
		body: JSON.stringify(body),
	}) as any;
}

// Build a form-data POST request to a given pathname.
function formRequest(pathname: string, body: Record<string, string>, headers: Record<string, string> = {}): Request {
	const form = new URLSearchParams();
	for (const [k, v] of Object.entries(body)) form.set(k, v);
	return new Request(`https://x${pathname}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
		body: form.toString(),
	}) as any;
}

// A valid step id (1-7 are valid per VALID_STEPS in verification-session.ts).
const VALID_STEP = 2;
// A recent accessTime (now) so the max-duration check passes.
const NOW = Date.now();

describe('handleResultRoutes — common preamble', () => {
	it('returns null for non-POST methods', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = new Request('https://x/result/success', { method: 'GET' });
		const result = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		expect(result).toBeNull();
	});

	it('returns null for an unmatched pathname', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/unknown', { stepId: VALID_STEP });
		const result = await handleResultRoutes(req as any, env, new URL('https://x/result/unknown'));
		expect(result).toBeNull();
	});

	it('non-object JSON body (bare string) → 30000 Invalid request body, HTTP 400', async () => {
		// typeof 'object' rejects primitives; a bare JSON string is not an object.
		// (Note: an array is technically typeof 'object' in JS and would pass the
		// guard, so we use a string primitive to exercise the non-object branch.)
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = new Request('https://x/result/success', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify('just a string'),
		});
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(400);
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30000, msg: 'Invalid request body' } });
	});

	it('non-object JSON body (number) → 30000 Invalid request body, HTTP 400', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = new Request('https://x/result/success', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(42),
		});
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(400);
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30000, msg: 'Invalid request body' } });
	});

	it('malformed JSON body → 30000 Malformed request body, HTTP 400', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = new Request('https://x/result/success', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: '{not json',
		});
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(400);
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30000, msg: 'Malformed request body' } });
	});
});

describe('handleResultRoutes — POST /result/success', () => {
	it('invalid stepId (0) → 30007 Invalid step id, HTTP 200', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: 0 });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30007, msg: 'Invalid step id' } });
	});

	it('invalid stepId (8 — outside 1-7) → 30007 Invalid step id', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: 8 });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30007, msg: 'Invalid step id' } });
	});

	it('invalid stepId (negative) → 30007 Invalid step id', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: -1 });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30007, msg: 'Invalid step id' } });
	});

	it('invalid stepId (NaN string) → safeParseInt falls back to 0 → 30007', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: 'abc' });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30007, msg: 'Invalid step id' } });
	});

	it('missing session cookie → 30010 Session not found', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: VALID_STEP });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30010, msg: 'Session not found' } });
	});

	it('DO getRequestSession throws → 30010 Session not found', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({ getRequestSession: new Error('DO boom') });
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30010, msg: 'Session not found' } });
	});

	it('DO getRequestSession returns null → 30010 Session not found', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({ getRequestSession: null });
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30010, msg: 'Session not found' } });
	});

	it('max-duration expired (accessTime in the past) → 30008 Test max allowed time expired', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW - 2_000_000 },
			updateState: { success: true },
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30008, msg: 'Test max allowed time expired' } });
	});

	it('missing accessTime → 30008 (fail-closed)', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1' },
			updateState: { success: true },
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30008, msg: 'Test max allowed time expired' } });
	});

	it('wrong token vs successKey → 30009 Invalid token', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, successKey: 'real-key' },
			updateState: { success: true },
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: VALID_STEP, token: 'wrong-key' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30009, msg: 'Invalid token' } });
	});

	it('DO end throws → 30010 Failed to save session data', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, successKey: 'tok' },
			end: new Error('end failed'),
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30010, msg: 'Failed to save session data' } });
	});

	it('DO end returns no payload (null) → 30010 Failed to save session data', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, successKey: 'tok' },
			end: null,
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30010, msg: 'Failed to save session data' } });
	});

	it('DO end returns empty payload string → 30010 Failed to save session data', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, successKey: 'tok' },
			end: { payload: '' },
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		// Empty string is falsy, so the `!endResult.payload` guard fires.
		expect(body).toEqual({ error: { code: 30010, msg: 'Failed to save session data' } });
	});

	it('DO end returns stateInt !== SUCCESS (FAILED) → 30010 Session is not in a success state', async () => {
		// Defense-in-depth: even though the route asked the DO to end as SUCCESS,
		// the DO reports the stored terminal state is FAILED (3). The route must
		// refuse to report success to the partner.
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, successKey: 'tok' },
			end: { payload: 'some-payload', stateInt: 3 },
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30010, msg: 'Session is not in a success state' } });
	});

	it('happy path → {content:{successPayload, success:1}} + isAgeVerified Set-Cookie', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, successKey: 'tok' },
			end: { payload: 'encrypted-success-payload', stateInt: 2 },
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/success', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		expect(res).not.toBeNull();
		const body = await res!.json();
		expect(body).toEqual({ content: { successPayload: 'encrypted-success-payload', success: 1 } });
		const setCookie = res!.headers.get('Set-Cookie');
		expect(setCookie).not.toBeNull();
		expect(setCookie).toContain('isAgeVerified=encrypted-success-payload');
		expect(setCookie).toContain('Path=/');
		// config.cookie.maxAge = 7*24*60*60*1000 ms → Max-Age = maxAge/1000 = 604800
		expect(setCookie).toContain('Max-Age=604800');
		expect(setCookie).toContain('Secure');
		expect(setCookie).toContain('HttpOnly');
		expect(setCookie).toContain('SameSite=Lax');
	});

	it('happy path also accepts form-encoded body', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, successKey: 'tok' },
			end: { payload: 'enc', stateInt: 2 },
		});
		const handleResultRoutes = await importHandler();
		const req = formRequest('/result/success', { stepId: String(VALID_STEP), token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/success'));
		const body = await res!.json();
		expect(body).toEqual({ content: { successPayload: 'enc', success: 1 } });
	});
});

describe('handleResultRoutes — POST /result/fail', () => {
	it('invalid stepId (0) → 30011 Invalid step id', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/fail', { stepId: 0 });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/fail'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30011, msg: 'Invalid step id' } });
	});

	it('invalid stepId (8) → 30011 Invalid step id', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/fail', { stepId: 8 });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/fail'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30011, msg: 'Invalid step id' } });
	});

	it('missing session cookie → 30014 Session not found (NOT 30010)', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/fail', { stepId: VALID_STEP });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/fail'));
		const body = await res!.json();
		// /result/fail uses 30014 for session-not-found, distinct from /result/success's 30010.
		expect(body).toEqual({ error: { code: 30014, msg: 'Session not found' } });
	});

	it('DO getRequestSession returns null → 30014 Session not found', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({ getRequestSession: null });
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/fail', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/fail'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30014, msg: 'Session not found' } });
	});

	it('max-duration expired → 30012 Test max allowed time expired', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW - 2_000_000 },
			updateState: { success: true },
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/fail', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/fail'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30012, msg: 'Test max allowed time expired' } });
	});

	it('wrong token vs failKey → 30013 Invalid token', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, failKey: 'real-fail-key' },
			updateState: { success: true },
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/fail', { stepId: VALID_STEP, token: 'wrong-fail-key' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/fail'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30013, msg: 'Invalid token' } });
	});

	it('DO end throws → 30014 Failed to save session data', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, failKey: 'tok' },
			end: new Error('end failed'),
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/fail', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/fail'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30014, msg: 'Failed to save session data' } });
	});

	it('DO end returns payload that is not a string → 30014 Failed to save session data', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, failKey: 'tok' },
			// /result/fail requires typeof payload === 'string'; an object fails.
			end: { payload: { not: 'a string' } },
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/fail', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/fail'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30014, msg: 'Failed to save session data' } });
	});

	it('DO end returns stateInt !== FAILED (SUCCESS) → 30014 Session is not in a fail state', async () => {
		// Defense-in-depth: even though the route asked the DO to end as FAILED,
		// the DO reports the stored terminal state is SUCCESS (2). The route must
		// refuse to report failure to the partner.
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, failKey: 'tok' },
			end: { payload: 'some-payload', stateInt: 2 },
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/fail', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/fail'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30014, msg: 'Session is not in a fail state' } });
	});

	it('happy path → {content:{success:1}}, no Set-Cookie', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({
			getRequestSession: { sessionStartId: 'start1', accessTime: NOW, failKey: 'tok' },
			end: { payload: 'fail-payload-string', stateInt: 3 },
		});
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/fail', { stepId: VALID_STEP, token: 'tok' }, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/fail'));
		expect(res).not.toBeNull();
		const body = await res!.json();
		expect(body).toEqual({ content: { success: 1 } });
		// /result/fail never mints an isAgeVerified cookie.
		expect(res!.headers.get('Set-Cookie')).toBeNull();
	});
});

describe('handleResultRoutes — POST /result/isSuccess', () => {
	it('missing session cookie → 30010 Session not found', async () => {
		const { env } = makeEnv();
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/isSuccess', {});
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/isSuccess'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30010, msg: 'Session not found' } });
	});

	it('DO isPayloadValidated throws → 30010 Session lookup failed', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({ isPayloadValidated: new Error('lookup boom') });
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/isSuccess', {}, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/isSuccess'));
		const body = await res!.json();
		expect(body).toEqual({ error: { code: 30010, msg: 'Session lookup failed' } });
	});

	it('validated → {content:{isValidated:true, success:1}}', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({ isPayloadValidated: { isValidated: true } });
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/isSuccess', {}, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/isSuccess'));
		const body = await res!.json();
		expect(body).toEqual({ content: { isValidated: true, success: 1 } });
	});

	it('not validated → {content:{isValidated:false, success:1}}', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({ isPayloadValidated: { isValidated: false } });
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/isSuccess', {}, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/isSuccess'));
		const body = await res!.json();
		expect(body).toEqual({ content: { isValidated: false, success: 1 } });
	});

	it('checkResult missing isValidated field → defaults to false', async () => {
		const cookie = await makeSessionCookieHeader('hash1', 'req1');
		const { env } = makeEnv({ isPayloadValidated: {} });
		const handleResultRoutes = await importHandler();
		const req = jsonRequest('/result/isSuccess', {}, { Cookie: cookie });
		const res = await handleResultRoutes(req as any, env, new URL('https://x/result/isSuccess'));
		const body = await res!.json();
		// `checkResult?.isValidated || false` → undefined || false === false
		expect(body).toEqual({ content: { isValidated: false, success: 1 } });
	});
});
