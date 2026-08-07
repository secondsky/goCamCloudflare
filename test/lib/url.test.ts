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
