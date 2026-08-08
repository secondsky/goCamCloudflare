/**
 * Shared test helper: derives the same `aesKey`/`hmacKey` the production code
 * uses, so individual test files don't duplicate the HKDF derivation logic.
 *
 * Mirrors src/config.ts:
 *   const aesKey  = await hkdfDerive(key, 'avs/aes/v1', 32);
 *   const hmacKey = await hkdfDerive(key, 'avs/hmac/v1', 32);
 */
import { hkdfDerive } from '../../src/lib/crypto-utils';

/**
 * A valid 32-byte UTF-8 passphrase suitable for HKDF key derivation in tests.
 * `'a'.repeat(32)` is used (not a random value) so derived keys are stable
 * across runs and easy to assert against in snapshots/golden vectors.
 */
export const TEST_PASSPHRASE: string = 'a'.repeat(32);

export interface TestKeys {
	aesKey: Uint8Array;
	hmacKey: Uint8Array;
}

/**
 * Derive the AES and HMAC subkeys from `TEST_PASSPHRASE` using the same
 * HKDF contexts as production code. Call once per test (cheap, but each
 * call hits WebCrypto).
 */
export async function getTestKeys(): Promise<TestKeys> {
	const aesKey = await hkdfDerive(TEST_PASSPHRASE, 'avs/aes/v1', 32);
	const hmacKey = await hkdfDerive(TEST_PASSPHRASE, 'avs/hmac/v1', 32);
	return { aesKey, hmacKey };
}
