/// <reference types="@cloudflare/vitest-pool-workers" />
import { describe, it, expect } from 'vitest';
import { SELF } from 'cloudflare:test';

/**
 * Integration tests for the Worker fetch handler (src/index.ts).
 *
 * These run in the Workers runtime pool via `cloudflare:test`. The `SELF`
 * fetcher invokes the Worker's own default-exported `fetch` handler, so the
 * hostname in the URL is irrelevant — only the pathname/method/body matter.
 *
 * Bindings (ENCRYPTION_KEY, ASSETS, VERIFICATION_SESSION, ANALYTICS) are
 * provided by the workers pool configuration in vitest.config.ts.
 */

describe('Worker fetch handler — security headers', () => {
	it('GET / returns 200', async () => {
		const response = await SELF.fetch('https://example.com/');
		expect(response.status).toBe(200);
	});

	it('sets X-Content-Type-Options: nosniff', async () => {
		const response = await SELF.fetch('https://example.com/');
		expect(response.headers.get('x-content-type-options')).toBe('nosniff');
	});

	it('sets Referrer-Policy: no-referrer', async () => {
		const response = await SELF.fetch('https://example.com/');
		expect(response.headers.get('referrer-policy')).toBe('no-referrer');
	});

	it('sets Strict-Transport-Security', async () => {
		const response = await SELF.fetch('https://example.com/');
		const sts = response.headers.get('strict-transport-security');
		expect(sts).not.toBeNull();
		expect(sts).toContain('max-age=');
	});
});

describe('Worker fetch handler — routing', () => {
	it('returns 404 for an unknown path', async () => {
		const response = await SELF.fetch('https://example.com/nonexistent-path-12345');
		expect(response.status).toBe(404);
	});

	it('responds to OPTIONS preflight with 2xx', async () => {
		const response = await SELF.fetch('https://example.com/', { method: 'OPTIONS' });
		expect(response.status).toBeGreaterThanOrEqual(200);
		expect(response.status).toBeLessThan(300);
	});
});

describe('Worker fetch handler — POST /getVerificationPayloadAndUrl error handling', () => {
	it('rejects a request with missing required fields', async () => {
		// Empty body: no callbackUrl / demoPageUrl / color config fields.
		const response = await SELF.fetch('https://example.com/getVerificationPayloadAndUrl', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: '',
		});

		// The handler returns an error response shape `{ error: { code, msg } }`
		// — never the success shape `{ content: { success: 1, ... } }`.
		const body = await response.json() as any;
		expect(body.error).toBeDefined();
		expect(body.content).toBeUndefined();
	});

	it('rejects an SSRF callback URL pointing at a private IP', async () => {
		// Include all required color config fields so the route progresses past
		// the field-presence check to the SSRF validation of callbackUrl.
		const formBody = new URLSearchParams({
			colorConfigBodyBackgroundInput: '#fff',
			colorConfigBodyForegroundInput: '#000',
			colorConfigButtonBackgroundInput: '#00f',
			colorConfigButtonForegroundInput: '#fff',
			colorConfigButtonForegroundCTAInput: '#f00',
			callbackUrl: 'http://127.0.0.1',
			demoPageUrl: 'https://example.com',
		});
		const response = await SELF.fetch('https://example.com/getVerificationPayloadAndUrl', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: formBody.toString(),
		});

		// 127.0.0.0/8 is in the SSRF blocklist; the route returns
		// `Invalid callback URL: private_range` before touching the network.
		const body = await response.json() as any;
		expect(body.error).toBeDefined();
		// The error message should reference the callback URL / private range.
		const msg: string = body.error?.msg ?? '';
		expect(msg.toLowerCase()).toMatch(/callback|private|url/);
	});
});

describe('Worker fetch handler — static assets', () => {
	it('serves a real asset under /static/ without a 500', async () => {
		// app/frontend/static/css/main.css exists in the repo, so the ASSETS
		// binding should serve it. Even if the binding ever 404s, the request
		// must reach the asset handler cleanly (not throw / 500).
		const response = await SELF.fetch('https://example.com/static/css/main.css');
		expect(response.status).toBeLessThan(500);
	});
});

/**
 * Rate-limit tests for checkRateLimit (module-private, exercised via SELF.fetch).
 *
 * The rateLimitMap is per-isolate and persists across tests in the same
 * workers-pool run, so each test MUST use a unique IP. We use a module-scoped
 * counter that yields a documentation-reserved IP (RFC 5737, 198.51.100.0/24)
 * per test so no two tests share a bucket.
 *
 * The window is 60s / 30 POSTs. Only POST requests are rate-limited.
 */
describe('Worker fetch handler — rate limiting', () => {
	// Unique-per-test IP counter (198.51.100.N — RFC 5737 doc-reserved range).
	// Start at .10 to leave room for any ad-hoc addresses used elsewhere.
	let ipCounter = 10;
	const uniqueIp = () => `198.51.100.${ipCounter++}`;

	it('allows 30 POSTs from a single IP within the window', async () => {
		const ip = uniqueIp();
		for (let i = 0; i < 30; i++) {
			const response = await SELF.fetch('https://example.com/callback', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'CF-Connecting-IP': ip,
				},
				body: JSON.stringify({}),
			});
			expect(response.status).not.toBe(429);
		}
	});

	it('returns 429 with {error:"rate_limited"} and Retry-After:60 on the 31st POST', async () => {
		const ip = uniqueIp();
		// Exhaust the 30-request window.
		for (let i = 0; i < 30; i++) {
			await SELF.fetch('https://example.com/callback', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'CF-Connecting-IP': ip,
				},
				body: JSON.stringify({}),
			});
		}
		// 31st POST must be rejected.
		const response = await SELF.fetch('https://example.com/callback', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'CF-Connecting-IP': ip,
			},
			body: JSON.stringify({}),
		});
		expect(response.status).toBe(429);
		expect(response.headers.get('retry-after')).toBe('60');
		const body = await response.json() as any;
		expect(body).toEqual({ error: 'rate_limited' });
	});

	it('does NOT rate-limit GET requests (31 GETs still succeed)', async () => {
		const ip = uniqueIp();
		// Send well over the POST limit as GETs — none should be throttled.
		for (let i = 0; i < 31; i++) {
			const response = await SELF.fetch('https://example.com/', {
				method: 'GET',
				headers: { 'CF-Connecting-IP': ip },
			});
			expect(response.status).toBe(200);
		}
	});

	it('falls back to the "unknown" bucket when CF-Connecting-IP is absent (no crash)', async () => {
		// Requests without CF-Connecting-IP share the 'unknown' bucket. Keep
		// the count low (2 POSTs) so we do not exhaust that shared bucket for
		// any other test. Assert they succeed (non-429) and do not throw.
		for (let i = 0; i < 2; i++) {
			const response = await SELF.fetch('https://example.com/callback', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({}),
			});
			expect(response.status).not.toBe(429);
		}
	});
});

/**
 * CORS / getAllowedOrigin tests.
 *
 * ALLOWED_ORIGINS is currently empty. In addSecurityHeaders the code sets
 * `Access-Control-Allow-Origin` AND `Vary: Origin` together, only when
 * `getAllowedOrigin(request)` returns a truthy value — so with an empty
 * allowlist BOTH headers are absent for every response, regardless of
 * whether the request carries an Origin header.
 *
 * (The preflight branch is the same: ACAO + Vary are set only when
 * allowedOrigin is truthy; Methods/Headers/Max-Age are always set.)
 */
describe('Worker fetch handler — CORS / getAllowedOrigin', () => {
	it('does NOT reflect an unallowed Origin (no ACAO, no Vary: Origin)', async () => {
		const response = await SELF.fetch('https://example.com/', {
			headers: { Origin: 'https://partner.example.com' },
		});
		// Allowlist empty → origin not reflected, and Vary: Origin is not set.
		expect(response.headers.get('access-control-allow-origin')).toBeNull();
		expect(response.headers.get('vary')).toBeNull();
	});

	it('sets neither Vary: Origin nor Access-Control-Allow-Origin when no Origin is present', async () => {
		const response = await SELF.fetch('https://example.com/');
		expect(response.headers.get('vary')).toBeNull();
		expect(response.headers.get('access-control-allow-origin')).toBeNull();
	});

	it('responds to OPTIONS preflight with 204 and CORS preflight headers, no ACAO', async () => {
		const response = await SELF.fetch('https://example.com/', {
			method: 'OPTIONS',
			headers: { Origin: 'https://partner.example.com' },
		});
		expect(response.status).toBe(204);
		expect(response.headers.get('access-control-allow-methods')).toBe('GET, POST, OPTIONS');
		expect(response.headers.get('access-control-allow-headers')).toBe('Content-Type');
		expect(response.headers.get('access-control-max-age')).toBe('86400');
		// Allowlist empty → no ACAO reflected.
		expect(response.headers.get('access-control-allow-origin')).toBeNull();
	});
});
