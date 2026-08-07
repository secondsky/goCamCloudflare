import { describe, it, expect, beforeEach, vi } from 'vitest';

// getConfig caches its result at module scope, so each test must reset the
// module registry and re-import getConfig fresh to exercise validation anew.
describe('getConfig validation', () => {
	beforeEach(async () => {
		vi.resetModules();
	});

	it('throws when ENCRYPTION_KEY is missing', async () => {
		const { getConfig } = await import('../src/config');
		expect(() => getConfig({ ENCRYPTION_KEY: '' } as any)).toThrow(/ENCRYPTION_KEY/);
	});

	it('throws when key is the known leaked example key', async () => {
		const { getConfig } = await import('../src/config');
		expect(() =>
			getConfig({ ENCRYPTION_KEY: 'zIkmW2zEgzlTLTRC5xeMbcOhHcE5sBHB' } as any),
		).toThrow();
	});

	it('throws when key is not 32 bytes', async () => {
		const { getConfig } = await import('../src/config');
		expect(() => getConfig({ ENCRYPTION_KEY: 'short' } as any)).toThrow();
	});

	it('succeeds with a valid 32-byte key', async () => {
		const { getConfig } = await import('../src/config');
		const cfg = getConfig({ ENCRYPTION_KEY: 'a'.repeat(32) } as any);
		expect(cfg.encryption.key).toBe('a'.repeat(32));
	});
});
