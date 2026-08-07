import { describe, it, expect, beforeEach, vi } from 'vitest';

// getConfig caches its result at module scope, so each test must reset the
// module registry and re-import getConfig fresh to exercise validation anew.
// Note: getConfig is async (it derives HKDF keys), so each call must be awaited.
describe('getConfig validation', () => {
	beforeEach(async () => {
		vi.resetModules();
	});

	it('throws when ENCRYPTION_KEY is missing', async () => {
		const { getConfig } = await import('../src/config');
		await expect(getConfig({ ENCRYPTION_KEY: '' } as any)).rejects.toThrow(/ENCRYPTION_KEY/);
	});

	it('throws when key is the known leaked example key', async () => {
		const { getConfig } = await import('../src/config');
		await expect(
			getConfig({ ENCRYPTION_KEY: 'zIkmW2zEgzlTLTRC5xeMbcOhHcE5sBHB' } as any),
		).rejects.toThrow();
	});

	it('throws when key is not 32 bytes', async () => {
		const { getConfig } = await import('../src/config');
		await expect(getConfig({ ENCRYPTION_KEY: 'short' } as any)).rejects.toThrow();
	});

	it('succeeds with a valid 32-byte key and derives aesKey/hmacKey', async () => {
		const { getConfig } = await import('../src/config');
		const cfg = await getConfig({ ENCRYPTION_KEY: 'a'.repeat(32) } as any);
		expect(cfg.encryption.key).toBe('a'.repeat(32));
		expect(cfg.encryption.aesKey).toBeInstanceOf(Uint8Array);
		expect(cfg.encryption.aesKey.byteLength).toBe(32);
		expect(cfg.encryption.hmacKey).toBeInstanceOf(Uint8Array);
		expect(cfg.encryption.hmacKey.byteLength).toBe(32);
		// AES and HMAC keys must be cryptographically independent
		expect(Array.from(cfg.encryption.aesKey)).not.toEqual(Array.from(cfg.encryption.hmacKey));
	});
});
