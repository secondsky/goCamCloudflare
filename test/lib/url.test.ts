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

describe('isSafeCallbackUrl — SSRF bypass vectors', () => {
	describe('numeric/decimal/hex/octal IP encoding', () => {
		// NOTE: Node's URL constructor normalizes integer IP encodings
		// (decimal/hex/octal) to dotted-decimal form before exposing
		// `hostname`, so the existing dotted-quad regexes catch them.
		// These tests pin that behavior — if a future runtime change ever
		// stops normalizing, these would become live SSRF bypasses.
		it('rejects decimal-encoded 127.0.0.1 (http://2130706433/)', () => {
			// 2130706433 === 0x7F000001 === 127.0.0.1
			const result = isSafeCallbackUrl('http://2130706433/');
			expect(result.ok).toBe(false);
		});

		it('rejects hex-encoded 127.0.0.1 (http://0x7f000001/)', () => {
			const result = isSafeCallbackUrl('http://0x7f000001/');
			expect(result.ok).toBe(false);
		});

		it('rejects octal-encoded 127.0.0.1 (http://0177.0.0.1/)', () => {
			const result = isSafeCallbackUrl('http://0177.0.0.1/');
			expect(result.ok).toBe(false);
		});

		it('rejects decimal-encoded cloud metadata (http://2852039166/)', () => {
			// 2852039166 === 169.254.169.254
			const result = isSafeCallbackUrl('http://2852039166/');
			expect(result.ok).toBe(false);
		});
	});

	describe('IPv6 edge cases', () => {
		// KNOWN BUG: [::] (IPv6 unspecified / "any") is not blocked.
		// It is the IPv6 equivalent of 0.0.0.0 and on some systems binds to
		// all interfaces including loopback, making it an SSRF vector.
		it.fails('rejects [::] (IPv6 any/unspecified address)', () => {
			const result = isSafeCallbackUrl('http://[::]/');
			expect(result.ok).toBe(false);
		});

		it('rejects [::ffff:127.0.0.1] (IPv4-mapped IPv6 loopback)', () => {
			const result = isSafeCallbackUrl('http://[::ffff:127.0.0.1]/');
			expect(result.ok).toBe(false);
		});
	});

	describe('valid public URLs are accepted', () => {
		it('accepts an unusual-but-valid public http URL', () => {
			const result = isSafeCallbackUrl('http://example.com/path');
			expect(result.ok).toBe(true);
		});

		it('accepts a public https callback URL', () => {
			const result = isSafeCallbackUrl('https://api.partner.com/callback');
			expect(result.ok).toBe(true);
		});
	});
});
