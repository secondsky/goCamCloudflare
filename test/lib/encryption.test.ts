import { describe, it, expect, beforeAll } from 'vitest';
import { AvsEncryption } from '../../src/lib/encryption';
import { hkdfDerive } from '../../src/lib/crypto-utils';

// Derive the AES keys the same way production does (HKDF out of a 32-byte
// passphrase). Different contexts (aes vs hmac) yield independent keys.
// Derived once in beforeAll to keep tests fast.
describe('AvsEncryption AES-GCM', () => {
	let TEST_KEY: Uint8Array;
	let WRONG_KEY: Uint8Array;

	beforeAll(async () => {
		TEST_KEY = await hkdfDerive('a'.repeat(32), 'avs/aes/v1', 32);
		WRONG_KEY = await hkdfDerive('b'.repeat(32), 'avs/aes/v1', 32);
	});

	it('encrypts and decrypts an object round-trip', async () => {
		const obj = { foo: 'bar', num: 42, nested: { a: true } };
		const encrypted = await AvsEncryption.encryptObject(obj, TEST_KEY);
		const decrypted = await AvsEncryption.decryptString(encrypted, TEST_KEY);
		expect(decrypted).toEqual(obj);
	});

	it('produces a different ciphertext each time (random IV)', async () => {
		const a = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		const b = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		expect(a).not.toBe(b);
	});

	it('uses the ivHex|:ciphertextHex format', async () => {
		const encrypted = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		expect(encrypted).toMatch(/^[0-9a-f]+\|:[0-9a-f]+$/);
	});

	it('fails to decrypt tampered ciphertext (GCM integrity check)', async () => {
		const encrypted = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		// Flip a bit in the ciphertext portion
		const tampered = encrypted.slice(0, -2) + (encrypted.slice(-2) === '00' ? '01' : '00');
		await expect(AvsEncryption.decryptString(tampered, TEST_KEY)).rejects.toThrow();
	});

	it('fails to decrypt with the wrong key', async () => {
		const encrypted = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		await expect(AvsEncryption.decryptString(encrypted, WRONG_KEY)).rejects.toThrow();
	});
});

describe('computePayloadHash', () => {
	it('returns a 64-char hex string', async () => {
		const hash = await AvsEncryption.computePayloadHash('abc123|:deadbeef');
		expect(hash).toMatch(/^[0-9a-f]{64}$/);
	});

	it('is deterministic for the same ciphertext', async () => {
		expect(await AvsEncryption.computePayloadHash('abc123|:deadbeef'))
			.toBe(await AvsEncryption.computePayloadHash('abc123|:deadbeef'));
	});

	it('differs for different ciphertexts', async () => {
		expect(await AvsEncryption.computePayloadHash('abc123|:deadbeef'))
			.not.toBe(await AvsEncryption.computePayloadHash('abc123|:cafebabe'));
	});
});
