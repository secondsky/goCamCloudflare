import { describe, it, expect } from 'vitest';
import { AvsEncryption } from '../../src/lib/encryption';

const TEST_KEY = 'a'.repeat(32); // 32 bytes

describe('AvsEncryption AES-GCM', () => {
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
		await expect(AvsEncryption.decryptString(encrypted, 'b'.repeat(32))).rejects.toThrow();
	});
});
