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

describe('Worker fetch handler — HEAD requests', () => {
	// HEAD must return the same status/headers as GET but with no body.
	// Before the fix, HEAD fell through route handlers (which only match GET)
	// and returned 404. See BUG-06 in docs/qa/test-report.md.
	it('HEAD / returns 200 with the same content-type as GET', async () => {
		const getResponse = await SELF.fetch('https://example.com/');
		const headResponse = await SELF.fetch('https://example.com/', { method: 'HEAD' });
		expect(headResponse.status).toBe(200);
		expect(headResponse.headers.get('content-type')).toBe(getResponse.headers.get('content-type'));
	});

	it('HEAD /test returns 200', async () => {
		const response = await SELF.fetch('https://example.com/test', { method: 'HEAD' });
		expect(response.status).toBe(200);
	});

	it('HEAD /terms returns 200', async () => {
		const response = await SELF.fetch('https://example.com/terms', { method: 'HEAD' });
		expect(response.status).toBe(200);
	});

	it('HEAD /token returns 200', async () => {
		const response = await SELF.fetch('https://example.com/token', { method: 'HEAD' });
		expect(response.status).toBe(200);
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
