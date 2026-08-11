import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request } from '@cloudflare/workers-types';

// ─── handleIndexRoutes direct handler tests ───
//
// Mirrors the pattern in test/routes/token.test.ts and result.test.ts:
// getConfig caches its result at module scope keyed by ENCRYPTION_KEY, so we
// vi.resetModules() before each test and re-import the handler fresh. The mock
// env includes a VERIFICATION_SESSION DO stub (the index.ts handler never hits
// the DO in the branches we test, but Env typing requires the binding) plus an
// ANALYTICS writeDataPoint mock that /callback asserts against.

// getConfig caches its result at module scope keyed by ENCRYPTION_KEY. Reset
// modules before each test so every test re-derives config from the mock env.
beforeEach(() => {
	vi.resetModules();
});

// Build a mock Env. `writeDataPoint` is a vi.fn() so /callback tests can assert
// the exact data-point shape. The VERIFICATION_SESSION DO stub is unused by the
// index.ts branches under test but is required for Env typing.
function makeEnv(): { env: any; writeDataPoint: ReturnType<typeof vi.fn> } {
	const writeDataPoint = vi.fn();
	const fetchMock = vi.fn(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));
	const stub = { fetch: fetchMock };
	return {
		env: {
			VERIFICATION_SESSION: {
				idFromName: vi.fn().mockReturnValue('do-id-123'),
				get: vi.fn().mockReturnValue(stub),
			},
			ANALYTICS: { writeDataPoint } as any,
			ASSETS: {} as any,
			ENCRYPTION_KEY: 'a'.repeat(32),
			ENCRYPTION_ALGORITHM: 'AES-GCM',
			ENABLE_FRONTEND_DEBUG: 'false',
		},
		writeDataPoint,
	};
}

// Import dynamically after vi.resetModules() so getConfig is fresh per test.
async function importHandler() {
	const mod = await import('../../src/routes/index');
	return mod.handleIndexRoutes;
}

// The 5 color form fields the /getVerificationPayloadAndUrl endpoint reads.
const VALID_COLORS = {
	colorConfigBodyBackgroundInput: '#ffffff',
	colorConfigBodyForegroundInput: '#000000',
	colorConfigButtonBackgroundInput: '#9acd1f',
	colorConfigButtonForegroundInput: '#ffffff',
	colorConfigButtonForegroundCTAInput: '#ffffff',
};

// Build a complete valid form body for /getVerificationPayloadAndUrl. Individual
// tests delete or override keys to exercise specific error branches.
function fullFormBody(overrides: Record<string, string> = {}): Record<string, string> {
	return {
		...VALID_COLORS,
		callbackUrl: 'https://partner.example.com/cb',
		demoPageUrl: 'https://partner.example.com/demo',
		...overrides,
	};
}

// Build a form-data (URL-encoded) POST Request. `cf` and CF-Connecting-IP are
// set by default so the happy path is reachable; the missing-cf test omits them.
function formRequest(
	pathname: string,
	body: Record<string, string>,
	opts: { cf?: any; ip?: string } = {},
): Request {
	const form = new URLSearchParams();
	for (const [k, v] of Object.entries(body)) form.set(k, v);
	const headers: Record<string, string> = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'CF-Connecting-IP': opts.ip ?? '203.0.113.10',
	};
	const init: any = {
		method: 'POST',
		headers,
		body: form.toString(),
	};
	if (opts.cf !== undefined) init.cf = opts.cf;
	return new Request(`https://example.com${pathname}`, init) as any;
}

// Build a JSON POST Request.
function jsonRequest(
	pathname: string,
	body: unknown,
	opts: { cf?: any; ip?: string } = {},
): Request {
	const headers: Record<string, string> = {
		'Content-Type': 'application/json',
		'CF-Connecting-IP': opts.ip ?? '203.0.113.10',
	};
	const init: any = {
		method: 'POST',
		headers,
		body: JSON.stringify(body),
	};
	if (opts.cf !== undefined) init.cf = opts.cf;
	return new Request(`https://example.com${pathname}`, init) as any;
}

// A valid cf object for the happy path.
const VALID_CF = { country: 'US', regionCode: 'CA' } as any;

describe('handleIndexRoutes — GET routes', () => {
	it('GET / returns 200 text/html with home page marker', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/', { method: 'GET' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		expect(res!.headers.get('Content-Type')).toBe('text/html; charset=utf-8');
		const body = await res!.text();
		// renderHome emits a hero heading "Age verification system" and an
		// app-data script block (renderBase). Both are stable markers.
		expect(body).toContain('Age verification system');
		expect(body).toContain('id="app-data"');
	});

	it('GET /test returns 200 with body "test"', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/test', { method: 'GET' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/test'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		const body = await res!.text();
		expect(body).toBe('test');
	});

	it('GET /terms returns 200 text/html with Terms title, "/" link, and noindex meta', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/terms', { method: 'GET' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/terms'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		expect(res!.headers.get('Content-Type')).toBe('text/html; charset=utf-8');
		const body = await res!.text();
		expect(body).toContain('Terms and Conditions');
		expect(body).toContain('noindex');
		// The "Go Back" button links back to "/".
		expect(body).toContain('href="/"');
	});

	it('GET /terms/ (trailing slash) returns the same terms page', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/terms/', { method: 'GET' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/terms/'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		const body = await res!.text();
		expect(body).toContain('Terms and Conditions');
		expect(body).toContain('noindex');
	});

	it('unknown pathname returns null', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/no-such-path', { method: 'GET' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/no-such-path'));
		expect(res).toBeNull();
	});

	it('non-matching method on a known path returns null', async () => {
		// /getVerificationPayloadAndUrl only handles POST; GET must fall through.
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/getVerificationPayloadAndUrl', { method: 'GET' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).toBeNull();
	});
});

describe('handleIndexRoutes — POST /getVerificationPayloadAndUrl', () => {
	it('empty form body → all fields undefined → 30000 Invalid payload config', async () => {
		// NOTE: The brief describes a "formData() throws → 30000 Malformed
		// request body" branch, but src/routes/index.ts line 76 does NOT wrap
		// request.formData() in try/catch. In practice undici's formData() is
		// extremely hard to make throw (it tolerates almost any input,
		// including a bare NUL byte, by parsing it as an empty/odd form). So
		// the documented "Malformed request body" envelope is unreachable for
		// this endpoint in the current code. The closest reachable failure is
		// an empty form, which surfaces every field as undefined and hits the
		// "Invalid payload config" guard at lines 86-95. See Concerns.
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/getVerificationPayloadAndUrl', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: '',
		});
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Invalid payload config' } });
	});

	it('missing callbackUrl → 30000 Invalid payload config', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const body = fullFormBody();
		delete (body as any).callbackUrl;
		const req = formRequest('/getVerificationPayloadAndUrl', body, { cf: VALID_CF });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Invalid payload config' } });
	});

	it('missing a color field (colorConfigButtonForegroundCTAInput) → 30000 Invalid payload config', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const body = fullFormBody();
		delete (body as any).colorConfigButtonForegroundCTAInput;
		const req = formRequest('/getVerificationPayloadAndUrl', body, { cf: VALID_CF });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Invalid payload config' } });
	});

	it('callbackUrl is an empty string → 30000 Invalid payload config', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = formRequest('/getVerificationPayloadAndUrl', fullFormBody({ callbackUrl: '' }), { cf: VALID_CF });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Invalid payload config' } });
	});

	it('callbackUrl is only whitespace → 30000 Invalid payload config', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = formRequest('/getVerificationPayloadAndUrl', fullFormBody({ callbackUrl: '   ' }), { cf: VALID_CF });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Invalid payload config' } });
	});

	it('unsafe callbackUrl (private 192.168 range) → 30000 Invalid callback URL: private_range', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = formRequest(
			'/getVerificationPayloadAndUrl',
			fullFormBody({ callbackUrl: 'https://192.168.1.1/exfil' }),
			{ cf: VALID_CF },
		);
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Invalid callback URL: private_range' } });
	});

	it('unsafe callbackUrl (localhost) → 30000 Invalid callback URL: loopback', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = formRequest(
			'/getVerificationPayloadAndUrl',
			fullFormBody({ callbackUrl: 'http://localhost:8080/cb' }),
			{ cf: VALID_CF },
		);
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Invalid callback URL: loopback' } });
	});

	it('invalid demoPageUrl → 30000 Invalid demo page URL', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = formRequest(
			'/getVerificationPayloadAndUrl',
			fullFormBody({ demoPageUrl: 'not-a-url' }),
			{ cf: VALID_CF },
		);
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Invalid demo page URL' } });
	});

	it('missing request.cf → 30000 Unable to determine client location', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		// No cf, no CF-Connecting-IP header.
		const req = formRequest('/getVerificationPayloadAndUrl', fullFormBody(), {});
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({
			error: {
				code: 30000,
				msg: 'Unable to determine client location. This service must be accessed via the Cloudflare edge.',
			},
		});
	});

	it('cf present but CF-Connecting-IP missing → 30000 Unable to determine client location', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = formRequest('/getVerificationPayloadAndUrl', fullFormBody(), { cf: VALID_CF, ip: '' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({
			error: {
				code: 30000,
				msg: 'Unable to determine client location. This service must be accessed via the Cloudflare edge.',
			},
		});
	});

	it('happy path → success envelope; payload decrypts to 5 colors; urls contain token paths', async () => {
		const { AvsEncryption } = await import('../../src/lib/encryption');
		const { getTestKeys } = await import('../helpers/crypto-keys');
		const { aesKey } = await getTestKeys();

		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = formRequest('/getVerificationPayloadAndUrl', fullFormBody(), { cf: VALID_CF });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json.content).toBeDefined();
		expect(json.content.success).toBe(1);
		expect(typeof json.content.payload).toBe('string');
		expect(typeof json.content.url).toBe('string');
		expect(typeof json.content.iframeUrl).toBe('string');
		// The redirect URL is built on demoPageUrl.origin and points at /token?d=
		expect(json.content.url).toContain('/token?d=');
		expect(json.content.url).toContain('https://partner.example.com');
		// The iframe URL points at /token/iframeCheck?d=
		expect(json.content.iframeUrl).toContain('/token/iframeCheck?d=');
		expect(json.content.iframeUrl).toContain('https://partner.example.com');

		// Decrypt the payload and assert the 5 color inputs round-trip.
		// Note the nesting from src/routes/index.ts: colorConfig.body holds
		// background/foreground/button, and button holds its own three keys.
		const decrypted = await AvsEncryption.decryptString(json.content.payload, aesKey);
		expect(decrypted.userData.colorConfig.body.background).toBe('#ffffff');
		expect(decrypted.userData.colorConfig.body.foreground).toBe('#000000');
		expect(decrypted.userData.colorConfig.body.button.background).toBe('#9acd1f');
		expect(decrypted.userData.colorConfig.body.button.foreground).toBe('#ffffff');
		expect(decrypted.userData.colorConfig.body.button.foregroundCallToAction).toBe('#ffffff');
		// Plus the geo/UA metadata the handler records.
		expect(decrypted.userIpCountry).toBe('US');
		expect(decrypted.userIpState).toBe('CA');
		expect(decrypted.callbackUrl).toBe('https://partner.example.com/cb');
	});

	it('happy path with no demoPageUrl uses request url.origin', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const body = fullFormBody();
		delete (body as any).demoPageUrl;
		const req = formRequest('/getVerificationPayloadAndUrl', body, { cf: VALID_CF });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/getVerificationPayloadAndUrl'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		// With no demoPageUrl, the handler falls back to url.origin (example.com).
		expect(json.content.url).toContain('https://example.com/token?d=');
		expect(json.content.iframeUrl).toContain('https://example.com/token/iframeCheck?d=');
	});
});

describe('handleIndexRoutes — POST /validateVerificationPayload', () => {
	it('non-object JSON body (bare string) → 30000 Invalid request body, HTTP 400', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/validateVerificationPayload', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify('a string'),
		});
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/validateVerificationPayload'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(400);
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Invalid request body' } });
	});

	it('non-object JSON body (number) → 30000 Invalid request body, HTTP 400', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/validateVerificationPayload', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(42),
		});
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/validateVerificationPayload'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(400);
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Invalid request body' } });
	});

	it('malformed JSON → 30000 Malformed request body, HTTP 400', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/validateVerificationPayload', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: '{not json',
		});
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/validateVerificationPayload'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(400);
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Malformed request body' } });
	});

	it('verificationPayload undefined → 30001 Invalid payload', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = jsonRequest('/validateVerificationPayload', { other: 'value' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/validateVerificationPayload'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30001, msg: 'Invalid payload' } });
	});

	it('decrypt throws (garbage payload) → 30002 Verification payload integrity check failed', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = jsonRequest('/validateVerificationPayload', { verificationPayload: 'not-encrypted' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/validateVerificationPayload'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30002, msg: 'Verification payload integrity check failed' } });
	});

	it('payload missing verificationResult → 30002 Verification payload integrity check failed', async () => {
		const { AvsEncryption } = await import('../../src/lib/encryption');
		const { getTestKeys } = await import('../helpers/crypto-keys');
		const { aesKey } = await getTestKeys();
		const payload = await AvsEncryption.encryptObject({ other: 'no-result-key' }, aesKey);

		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = jsonRequest('/validateVerificationPayload', { verificationPayload: payload });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/validateVerificationPayload'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30002, msg: 'Verification payload integrity check failed' } });
	});

	it('stateInt !== 2 → 30003 Payload state invalid', async () => {
		const { AvsEncryption } = await import('../../src/lib/encryption');
		const { getTestKeys } = await import('../helpers/crypto-keys');
		const { aesKey } = await getTestKeys();
		const payload = await AvsEncryption.encryptObject(
			{ verificationResult: { stateInt: 1, sessionId: 'xyz' } },
			aesKey,
		);

		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = jsonRequest('/validateVerificationPayload', { verificationPayload: payload });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/validateVerificationPayload'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30003, msg: 'Payload state invalid' } });
	});

	it('happy path (stateInt===2) → {content:{sessionId, success:1}}', async () => {
		const { AvsEncryption } = await import('../../src/lib/encryption');
		const { getTestKeys } = await import('../helpers/crypto-keys');
		const { aesKey } = await getTestKeys();
		const payload = await AvsEncryption.encryptObject(
			{ verificationResult: { stateInt: 2, sessionId: 'xyz' } },
			aesKey,
		);

		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = jsonRequest('/validateVerificationPayload', { verificationPayload: payload });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/validateVerificationPayload'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ content: { sessionId: 'xyz', success: 1 } });
	});
});

describe('handleIndexRoutes — POST /callback', () => {
	it('non-object JSON body (bare string) → 30000 Invalid request body, HTTP 400', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/callback', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify('a string'),
		});
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/callback'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(400);
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Invalid request body' } });
	});

	it('malformed JSON → 30000 Malformed request body, HTTP 400', async () => {
		const { env } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = new Request('https://example.com/callback', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: '{not json',
		});
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/callback'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(400);
		const json = await res!.json();
		expect(json).toEqual({ error: { code: 30000, msg: 'Malformed request body' } });
	});

	it('happy path writes data point with stateInt + sessionId', async () => {
		const { env, writeDataPoint } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = jsonRequest('/callback', { stateInt: 2, sessionId: 'sess-abc' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/callback'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ content: { success: 1 } });
		expect(writeDataPoint).toHaveBeenCalledTimes(1);
		const arg = writeDataPoint.mock.calls[0][0];
		expect(arg.blobs).toEqual(['callback_received', '2', 'sess-abc']);
		expect(arg.indexes).toEqual(['callback']);
		expect(arg.doubles).toHaveLength(1);
		expect(typeof arg.doubles[0]).toBe('number');
	});

	it('happy path with stateInt undefined → state blob is "unknown"', async () => {
		const { env, writeDataPoint } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = jsonRequest('/callback', { sessionId: 'sess-x' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/callback'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		expect(json).toEqual({ content: { success: 1 } });
		expect(writeDataPoint).toHaveBeenCalledTimes(1);
		const arg = writeDataPoint.mock.calls[0][0];
		expect(arg.blobs[0]).toBe('callback_received');
		expect(arg.blobs[1]).toBe('unknown');
		expect(arg.blobs[2]).toBe('sess-x');
	});

	it('happy path with non-string sessionId → sessionId blob is ""', async () => {
		const { env, writeDataPoint } = makeEnv();
		const handleIndexRoutes = await importHandler();
		const req = jsonRequest('/callback', { stateInt: 2, sessionId: 12345 });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/callback'));
		expect(res).not.toBeNull();
		await res!.json();
		const arg = writeDataPoint.mock.calls[0][0];
		expect(arg.blobs[2]).toBe('');
	});

	it('ANALYTICS.writeDataPoint throws → still returns {content:{success:1}}', async () => {
		const { env, writeDataPoint } = makeEnv();
		writeDataPoint.mockImplementation(() => { throw new Error('analytics down'); });
		const handleIndexRoutes = await importHandler();
		const req = jsonRequest('/callback', { stateInt: 2, sessionId: 'sess-swallow' });
		const res = await handleIndexRoutes(req as any, env, new URL('https://example.com/callback'));
		expect(res).not.toBeNull();
		const json = await res!.json();
		// Analytics failure is swallowed — the callback still succeeds.
		expect(json).toEqual({ content: { success: 1 } });
	});
});
