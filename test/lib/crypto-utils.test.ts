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
