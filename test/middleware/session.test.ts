import { describe, it, expect, beforeAll } from 'vitest';
import {
	parseCookies,
	getSessionContextFromRequest,
	createSessionCookie,
	withCookie,
} from '../../src/middleware/session';
import { getTestKeys } from '../helpers/crypto-keys';
import { hkdfDerive } from '../../src/lib/crypto-utils';

const COOKIE_NAME = 'avs-session';

/**
 * Extract the cookie value (the part between `COOKIE_NAME=` and the first `;`)
 * from a Set-Cookie header string produced by createSessionCookie.
 *
 * Example input:
 *   "avs-session=hash:req.abc123...; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=1200"
 * Returns:
 *   "hash:req.abc123..."
 */
function extractCookieValue(setCookie: string): string {
	const prefix = `${COOKIE_NAME}=`;
	const startIdx = setCookie.indexOf(prefix) + prefix.length;
	const endIdx = setCookie.indexOf(';', startIdx);
	return setCookie.slice(startIdx, endIdx === -1 ? undefined : endIdx);
}

describe('HMAC-signed session cookie middleware', () => {
	let hmacKey: Uint8Array;
	let wrongHmacKey: Uint8Array;

	beforeAll(async () => {
		// Primary key (derived from TEST_PASSPHRASE 'a'.repeat(32)).
		const keys = await getTestKeys();
		hmacKey = keys.hmacKey;
		// A genuinely different HMAC key for the "wrong key" test. Deriving from a
		// different passphrase guarantees the two keys are cryptographically
		// independent (the same HKDF context 'avs/hmac/v1' is used, but the input
		// keying material differs).
		wrongHmacKey = await hkdfDerive('b'.repeat(32), 'avs/hmac/v1', 32);
	});

	describe('round-trip', () => {
		it('createSessionCookie -> getSessionContextFromRequest returns the stored context', async () => {
			const setCookie = await createSessionCookie('hash123', 'reqSession456', hmacKey);
			const request = new Request('https://example.com/', {
				headers: { Cookie: setCookie.split(';')[0] },
			});
			const ctx = await getSessionContextFromRequest(request, hmacKey);
			expect(ctx).toEqual({ payloadHash: 'hash123', requestSessionId: 'reqSession456' });
		});
	});

	describe('tamper rejection', () => {
		it('rejects a flipped bit in the signature', async () => {
			const setCookie = await createSessionCookie('hash123', 'reqSession456', hmacKey);
			const value = extractCookieValue(setCookie);
			// value = "<sessionId>.<64-hex-sig>". Flip the last hex char of the sig
			// to a different valid hex char so the format check passes but the
			// HMAC verification fails.
			const lastChar = value[value.length - 1];
			const flippedChar = lastChar === 'a' ? 'b' : 'a';
			const tamperedValue = value.slice(0, -1) + flippedChar;
			const request = new Request('https://example.com/', {
				headers: { Cookie: `${COOKIE_NAME}=${tamperedValue}` },
			});
			expect(await getSessionContextFromRequest(request, hmacKey)).toBeNull();
		});

		it('rejects a cookie signed with a different HMAC key', async () => {
			// Sign with hmacKey (key A).
			const setCookie = await createSessionCookie('hash123', 'reqSession456', hmacKey);
			const value = extractCookieValue(setCookie);
			// Verify with wrongHmacKey (key B).
			const request = new Request('https://example.com/', {
				headers: { Cookie: `${COOKIE_NAME}=${value}` },
			});
			expect(await getSessionContextFromRequest(request, wrongHmacKey)).toBeNull();
		});
	});

	describe('format validation', () => {
		it('rejects a signature with 63 hex chars (one short)', async () => {
			const setCookie = await createSessionCookie('hash123', 'reqSession456', hmacKey);
			const value = extractCookieValue(setCookie);
			// Drop the last char of the 64-char signature -> 63 chars.
			const tamperedValue = value.slice(0, -1);
			const request = new Request('https://example.com/', {
				headers: { Cookie: `${COOKIE_NAME}=${tamperedValue}` },
			});
			expect(await getSessionContextFromRequest(request, hmacKey)).toBeNull();
		});

		it('rejects a signature with 65 hex chars (one long)', async () => {
			const setCookie = await createSessionCookie('hash123', 'reqSession456', hmacKey);
			const value = extractCookieValue(setCookie);
			// Append one extra hex char to the 64-char signature -> 65 chars.
			const tamperedValue = value + '0';
			const request = new Request('https://example.com/', {
				headers: { Cookie: `${COOKIE_NAME}=${tamperedValue}` },
			});
			expect(await getSessionContextFromRequest(request, hmacKey)).toBeNull();
		});

		it('rejects a value with no dot separator', async () => {
			// No '.' in the signed value -> verifySessionId returns null.
			const request = new Request('https://example.com/', {
				headers: { Cookie: `${COOKIE_NAME}=noDotHereJustHexdeadbeef` },
			});
			expect(await getSessionContextFromRequest(request, hmacKey)).toBeNull();
		});

		it('rejects a signed value whose payload has no colon separator', async () => {
			// Sign a value that contains no ':' so that verifySessionId succeeds
			// (the HMAC is valid) but decodeSessionValue returns null because the
			// SESSION_SEPARATOR (':') is absent. signSessionId is module-private,
			// so we recompute the HMAC manually using the same key and algorithm.
			// createSessionCookie joins payloadHash and requestSessionId with ':',
			// so it cannot produce a no-colon payload directly.
			const encoder = new TextEncoder();
			const cryptoKey = await crypto.subtle.importKey(
				'raw',
				hmacKey as unknown as BufferSource,
				{ name: 'HMAC', hash: 'SHA-256' },
				false,
				['sign'],
			);
			const sig = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode('noColonHere'));
			const sigHex = Array.from(new Uint8Array(sig))
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');
			const signedValue = `noColonHere.${sigHex}`;
			const request = new Request('https://example.com/', {
				headers: { Cookie: `${COOKIE_NAME}=${signedValue}` },
			});
			expect(await getSessionContextFromRequest(request, hmacKey)).toBeNull();
		});
	});

	describe('parseCookies', () => {
		it('parses multiple cookies including avs-session', () => {
			const request = new Request('https://example.com/', {
				headers: { Cookie: 'a=1; b=2; avs-session=xyz' },
			});
			expect(parseCookies(request)).toEqual({ a: '1', b: '2', 'avs-session': 'xyz' });
		});

		it('returns an empty object when there is no Cookie header', () => {
			const request = new Request('https://example.com/');
			expect(parseCookies(request)).toEqual({});
		});

		it('trims whitespace around names and values', () => {
			const request = new Request('https://example.com/', {
				headers: { Cookie: '  a=1 ;  b=2 ' },
			});
			expect(parseCookies(request)).toEqual({ a: '1', b: '2' });
		});
	});

	describe('withCookie', () => {
		it('appends Set-Cookie while preserving existing headers', () => {
			const original = new Response('body', {
				status: 201,
				headers: { 'Content-Type': 'application/json', 'X-Custom': 'yes' },
			});
			const cookieValue = 'avs-session=abc; Path=/; HttpOnly';
			const wrapped = withCookie(original, cookieValue);
			// Set-Cookie is appended.
			expect(wrapped.headers.get('Set-Cookie')).toBe(cookieValue);
			// Original headers are preserved.
			expect(wrapped.headers.get('Content-Type')).toBe('application/json');
			expect(wrapped.headers.get('X-Custom')).toBe('yes');
			// Status is preserved.
			expect(wrapped.status).toBe(201);
		});
	});

	describe('createSessionCookie attributes', () => {
		it('contains HttpOnly, Secure, SameSite=Lax, Max-Age=1200, and Path=/', async () => {
			const setCookie = await createSessionCookie('hash123', 'reqSession456', hmacKey);
			expect(setCookie).toContain('HttpOnly');
			expect(setCookie).toContain('Secure');
			expect(setCookie).toContain('SameSite=Lax');
			expect(setCookie).toContain('Max-Age=1200');
			expect(setCookie).toContain('Path=/');
			// Sanity: the cookie name and a signed value are present.
			expect(setCookie.startsWith(`${COOKIE_NAME}=`)).toBe(true);
			expect(setCookie).toMatch(/\.([0-9a-f]{64})/);
		});
	});
});
