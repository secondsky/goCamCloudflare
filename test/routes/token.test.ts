import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request } from '@cloudflare/workers-types';

// getConfig caches its result at module scope keyed by ENCRYPTION_KEY. Reset
// modules before each test so every test re-derives config from the mock env
// (mirrors the pattern in test/config.test.ts).
beforeEach(() => {
	vi.resetModules();
});

// Build a mock Env whose VERIFICATION_SESSION DO stub has a scripted .fetch.
// callDoJson calls `stub.fetch(new Request('http://do/<action>', {...}))` and
// parses `.json()`, so the mock returns Response objects keyed by action.
function makeEnv(startResponse: any, storeResponse: any = { success: true }): any {
	const fetchMock = vi.fn(async (req: Request) => {
		const url = new URL(req.url);
		const action = url.pathname.split('/').filter(Boolean).pop() || '';
		if (action === 'start') {
			if (startResponse instanceof Error) throw startResponse;
			return new Response(JSON.stringify(startResponse), { status: 200 });
		}
		if (action === 'storeRequestSession') {
			if (storeResponse instanceof Error) throw storeResponse;
			const status = storeResponse && typeof storeResponse === 'object' && storeResponse.__status
				? storeResponse.__status : 200;
			return new Response(JSON.stringify(storeResponse), { status });
		}
		return new Response(JSON.stringify({ ok: true }), { status: 200 });
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
	const mod = await import('../../src/routes/token');
	return mod.handleTokenRoutes;
}

describe('handleTokenRoutes', () => {
	it('returns null for non-GET methods', async () => {
		const { env } = makeEnv({});
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token?d=abc', { method: 'POST' });
		const result = await handleTokenRoutes(req as any, env, new URL('https://x/token?d=abc'));
		expect(result).toBeNull();
	});

	it('returns null for an unknown pathname', async () => {
		const { env } = makeEnv({});
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/unknown', { method: 'GET' });
		const result = await handleTokenRoutes(req as any, env, new URL('https://x/unknown'));
		expect(result).toBeNull();
	});

	it('returns null for root path', async () => {
		const { env } = makeEnv({});
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/', { method: 'GET' });
		const result = await handleTokenRoutes(req as any, env, new URL('https://x/'));
		expect(result).toBeNull();
	});

	it('/token with missing d param returns HTML 200 with error 30005 Invalid payload', async () => {
		const { env } = makeEnv({});
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		expect(res!.headers.get('Content-Type')).toBe('text/html; charset=utf-8');
		const body = await res!.text();
		expect(body).toContain('30005');
		expect(body).toContain('Invalid payload');
	});

	it('/token with empty d param returns HTML 200 with error 30005', async () => {
		const { env } = makeEnv({});
		const handleTokenRoutes = await importHandler();
		// d= present but empty value is still falsy for url.searchParams.get
		const req = new Request('https://x/token?d=', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token?d='));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		const body = await res!.text();
		expect(body).toContain('30005');
		expect(body).toContain('Invalid payload');
	});
});

describe('handleTokenRoutes — DO start session states', () => {
	it('start returns sessionState===4 (LINK_EXPIRED) → 30006 Invalid payload (no expired message in current code)', async () => {
		const { env } = makeEnv({ sessionId: 's1', sessionState: 4, linkBack: '/back' });
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token?d=abc', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token?d=abc'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		const body = await res!.text();
		// NOTE: the brief describes an override to "This verification link has expired..."
		// but the actual code (src/routes/token.ts lines 99-104) always renders
		// 30006 'Invalid payload' for any non-IN_PROGRESS sessionState.
		// See Concerns in task-1-report.md.
		expect(body).toContain('30006');
		expect(body).toContain('Invalid payload');
		expect(body).not.toContain('This verification link has expired');
	});

	it('start returns sessionState===5 (LINK_ALREADY_USED) → 30006 Invalid payload (no used message in current code)', async () => {
		const { env } = makeEnv({ sessionId: 's1', sessionState: 5, linkBack: '/back' });
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token?d=abc', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token?d=abc'));
		expect(res).not.toBeNull();
		const body = await res!.text();
		// NOTE: brief describes override to "This verification link has already been used..."
		// but actual code renders generic 30006 'Invalid payload'.
		expect(body).toContain('30006');
		expect(body).toContain('Invalid payload');
		expect(body).not.toContain('already been used');
	});

	it('start returns other non-IN_PROGRESS state (e.g. 2 SUCCESS) → 30006 Invalid payload', async () => {
		const { env } = makeEnv({ sessionId: 's1', sessionState: 2, linkBack: '/back' });
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token?d=abc', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token?d=abc'));
		expect(res).not.toBeNull();
		const body = await res!.text();
		expect(body).toContain('30006');
		expect(body).toContain('Invalid payload');
	});

	it('start returns missing sessionId → 30006 Invalid payload', async () => {
		const { env } = makeEnv({ sessionState: 1 });
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token?d=abc', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token?d=abc'));
		expect(res).not.toBeNull();
		const body = await res!.text();
		expect(body).toContain('30006');
		expect(body).toContain('Invalid payload');
	});

	it('start returns sessionId non-string → 30006 Invalid payload', async () => {
		const { env } = makeEnv({ sessionId: 123, sessionState: 1 });
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token?d=abc', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token?d=abc'));
		expect(res).not.toBeNull();
		const body = await res!.text();
		expect(body).toContain('30006');
	});

	it('start throws → swallowed, 30006 Invalid payload', async () => {
		const { env } = makeEnv(new Error('DO boom'));
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token?d=abc', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token?d=abc'));
		expect(res).not.toBeNull();
		const body = await res!.text();
		expect(body).toContain('30006');
		expect(body).toContain('Invalid payload');
	});

	it('start returns non-OK status (error field) → 30006 Invalid payload', async () => {
		// callDoJson throws when response has an `error` field
		const { env } = makeEnv({ error: 'internal', __status: 200 });
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token?d=abc', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token?d=abc'));
		expect(res).not.toBeNull();
		const body = await res!.text();
		expect(body).toContain('30006');
	});
});

describe('handleTokenRoutes — success path', () => {
	it('/token with valid payload + IN_PROGRESS session renders token page with app-data block', async () => {
		const { AvsEncryption } = await import('../../src/lib/encryption');
		const { getTestKeys } = await import('../helpers/crypto-keys');
		const { aesKey } = await getTestKeys();
		const payload = await AvsEncryption.encryptObject({ userIpCountry: 'FR' }, aesKey);

		const { env } = makeEnv({ sessionId: 'sess-123', sessionState: 1, linkBack: '/return' });
		const handleTokenRoutes = await importHandler();
		const req = new Request(`https://x/token?d=${encodeURIComponent(payload)}`, { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL(`https://x/token?d=${encodeURIComponent(payload)}`));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		expect(res!.headers.get('Content-Type')).toBe('text/html; charset=utf-8');
		const body = await res!.text();
		// renderBase injects <script id="app-data" type="application/json">
		expect(body).toContain('id="app-data"');
		expect(body).toContain('avsMainContainer');
	});

	it('success path sets Set-Cookie header with avs-session=', async () => {
		const { AvsEncryption } = await import('../../src/lib/encryption');
		const { getTestKeys } = await import('../helpers/crypto-keys');
		const { aesKey } = await getTestKeys();
		const payload = await AvsEncryption.encryptObject({ userIpCountry: 'FR' }, aesKey);

		const { env } = makeEnv({ sessionId: 'sess-123', sessionState: 1, linkBack: '/return' });
		const handleTokenRoutes = await importHandler();
		const req = new Request(`https://x/token?d=${encodeURIComponent(payload)}`, { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL(`https://x/token?d=${encodeURIComponent(payload)}`));
		expect(res).not.toBeNull();
		const setCookie = res!.headers.get('Set-Cookie');
		expect(setCookie).not.toBeNull();
		expect(setCookie).toContain('avs-session=');
		expect(setCookie).toContain('HttpOnly');
		expect(setCookie).toContain('Secure');
		expect(setCookie).toContain('SameSite=Lax');
	});

	it('success path calls DO storeRequestSession after start', async () => {
		const { AvsEncryption } = await import('../../src/lib/encryption');
		const { getTestKeys } = await import('../helpers/crypto-keys');
		const { aesKey } = await getTestKeys();
		const payload = await AvsEncryption.encryptObject({ userIpCountry: 'FR' }, aesKey);

		const { env, fetchMock } = makeEnv({ sessionId: 'sess-123', sessionState: 1, linkBack: '/return' });
		const handleTokenRoutes = await importHandler();
		const req = new Request(`https://x/token?d=${encodeURIComponent(payload)}`, { method: 'GET' });
		await handleTokenRoutes(req as any, env, new URL(`https://x/token?d=${encodeURIComponent(payload)}`));
		const actions = fetchMock.mock.calls.map((c: any[]) => {
			const u = new URL(c[0].url);
			return u.pathname.split('/').filter(Boolean).pop();
		});
		expect(actions).toContain('start');
		expect(actions).toContain('storeRequestSession');
	});

	it('storeRequestSession throws → 30006 Invalid payload', async () => {
		const { AvsEncryption } = await import('../../src/lib/encryption');
		const { getTestKeys } = await import('../helpers/crypto-keys');
		const { aesKey } = await getTestKeys();
		const payload = await AvsEncryption.encryptObject({ userIpCountry: 'FR' }, aesKey);

		const { env } = makeEnv(
			{ sessionId: 'sess-123', sessionState: 1, linkBack: '/return' },
			new Error('storage failed'),
		);
		const handleTokenRoutes = await importHandler();
		const req = new Request(`https://x/token?d=${encodeURIComponent(payload)}`, { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL(`https://x/token?d=${encodeURIComponent(payload)}`));
		expect(res).not.toBeNull();
		const body = await res!.text();
		expect(body).toContain('30006');
		expect(body).toContain('Invalid payload');
	});

	it('decrypt throws (payload not encrypted with test key) → 30006 Invalid payload', async () => {
		// IN_PROGRESS session, but payload is garbage that cannot be decrypted
		const { env } = makeEnv({ sessionId: 'sess-123', sessionState: 1, linkBack: '/return' });
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token?d=not-a-valid-ciphertext', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token?d=not-a-valid-ciphertext'));
		expect(res).not.toBeNull();
		const body = await res!.text();
		expect(body).toContain('30006');
		expect(body).toContain('Invalid payload');
	});
});

describe('handleTokenRoutes — /token/iframeRender', () => {
	it('renders the token page (uses verificationVersion 2 internally)', async () => {
		const { AvsEncryption } = await import('../../src/lib/encryption');
		const { getTestKeys } = await import('../helpers/crypto-keys');
		const { aesKey } = await getTestKeys();
		const payload = await AvsEncryption.encryptObject({ userIpCountry: 'FR' }, aesKey);

		const { env } = makeEnv({ sessionId: 'sess-iframe', sessionState: 1, linkBack: '/back' });
		const handleTokenRoutes = await importHandler();
		const req = new Request(`https://x/token/iframeRender?d=${encodeURIComponent(payload)}`, { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL(`https://x/token/iframeRender?d=${encodeURIComponent(payload)}`));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		expect(res!.headers.get('Content-Type')).toBe('text/html; charset=utf-8');
		const body = await res!.text();
		// verificationVersion=2 (VERIFICATION_IFRAME_V1) is embedded in the
		// app-data JSON. The page renders identically to /token otherwise.
		expect(body).toContain('id="app-data"');
		// The token JSON encodes verificationVersion; confirm it is 2.
		const match = body.match(/<script id="app-data"[^>]*>([\s\S]*?)<\/script>/);
		expect(match).not.toBeNull();
		const parsed = JSON.parse(match![1]);
		expect(parsed.verificationVersion).toBe(2);
	});

	it('iframeRender with missing d param → 30005 Invalid payload', async () => {
		const { env } = makeEnv({});
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token/iframeRender', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token/iframeRender'));
		expect(res).not.toBeNull();
		const body = await res!.text();
		expect(body).toContain('30005');
		expect(body).toContain('Invalid payload');
	});
});

describe('handleTokenRoutes — /token/iframeCheck', () => {
	it('renders embed-check HTML with Content-Type text/html', async () => {
		const { env } = makeEnv({});
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token/iframeCheck', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token/iframeCheck'));
		expect(res).not.toBeNull();
		expect(res!.status).toBe(200);
		expect(res!.headers.get('Content-Type')).toBe('text/html; charset=utf-8');
		const body = await res!.text();
		// renderTokenEmbedCheck emits an app-data block + the iframeCheck script
		expect(body).toContain('id="app-data"');
		expect(body).toContain('avsFactoryIframeCheck.js');
	});

	it('reflects isAgeVerified=true from Cookie: isAgeVerified=...', async () => {
		const { env } = makeEnv({});
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token/iframeCheck', {
			method: 'GET',
			headers: { Cookie: 'isAgeVerified=some-payload-value' },
		});
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token/iframeCheck'));
		expect(res).not.toBeNull();
		const body = await res!.text();
		const match = body.match(/<script id="app-data"[^>]*>([\s\S]*?)<\/script>/);
		expect(match).not.toBeNull();
		const parsed = JSON.parse(match![1]);
		expect(parsed.isAgeVerified).toBe(true);
		expect(parsed.verificationPayload).toBe('some-payload-value');
	});

	it('missing isAgeVerified cookie → isAgeVerified false, verificationPayload null', async () => {
		const { env } = makeEnv({});
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token/iframeCheck', { method: 'GET' });
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token/iframeCheck'));
		expect(res).not.toBeNull();
		const body = await res!.text();
		const match = body.match(/<script id="app-data"[^>]*>([\s\S]*?)<\/script>/);
		expect(match).not.toBeNull();
		const parsed = JSON.parse(match![1]);
		expect(parsed.isAgeVerified).toBe(false);
		expect(parsed.verificationPayload).toBeNull();
	});

	it('empty isAgeVerified cookie value → isAgeVerified false', async () => {
		const { env } = makeEnv({});
		const handleTokenRoutes = await importHandler();
		const req = new Request('https://x/token/iframeCheck', {
			method: 'GET',
			headers: { Cookie: 'isAgeVerified=' },
		});
		const res = await handleTokenRoutes(req as any, env, new URL('https://x/token/iframeCheck'));
		expect(res).not.toBeNull();
		const body = await res!.text();
		const match = body.match(/<script id="app-data"[^>]*>([\s\S]*?)<\/script>/);
		expect(match).not.toBeNull();
		const parsed = JSON.parse(match![1]);
		expect(parsed.isAgeVerified).toBe(false);
		expect(parsed.verificationPayload).toBeNull();
	});
});
