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

describe('decryptString edge cases', () => {
	let TEST_KEY: Uint8Array;

	beforeAll(async () => {
		TEST_KEY = await hkdfDerive('a'.repeat(32), 'avs/aes/v1', 32);
	});

	it('throws when the separator is missing (no ":")', async () => {
		// indexOf(':') returns -1 → ivHex becomes '' and ciphertext becomes the
		// whole string. GCM decrypt should fail on the garbage inputs.
		await expect(AvsEncryption.decryptString('abc', TEST_KEY)).rejects.toThrow();
	});

	it('throws when the separator is at position 0 (empty IV hex)', async () => {
		// ivHex is '' (empty), ciphertext is 'abc'. Both decode to empty/garbage
		// and GCM decrypt rejects.
		await expect(AvsEncryption.decryptString(':abc', TEST_KEY)).rejects.toThrow();
	});

	it('throws on an empty string', async () => {
		await expect(AvsEncryption.decryptString('', TEST_KEY)).rejects.toThrow();
	});
});

describe('base64 encode/decode', () => {
	it('round-trips an object through base64EncodeObject and base64DecodeString', () => {
		const obj = { a: 1, b: 'hello' };
		const encoded = AvsEncryption.base64EncodeObject(obj);
		const decoded = AvsEncryption.base64DecodeString(encoded);
		expect(decoded).toEqual(obj);
	});

	it('throws when encoding an object containing non-Latin1 characters', () => {
		// btoa() only accepts Latin1 (code points U+0000–U+00FF). A character
		// outside that range — e.g. the snowman U+2603 — makes btoa throw.
		// (Note: 'é' U+00E9 is within Latin1 and does NOT throw in this runtime.)
		expect(() => AvsEncryption.base64EncodeObject({ text: 'snowman \u2603' })).toThrow();
	});
});

describe('computePayloadHash behavioral implication for dedup', () => {
	let TEST_KEY: Uint8Array;

	beforeAll(async () => {
		TEST_KEY = await hkdfDerive('a'.repeat(32), 'avs/aes/v1', 32);
	});

	it('produces different hashes for re-encryptions of the same plaintext', async () => {
		// Each encryptObject call uses a fresh random IV, so the ciphertext — and
		// therefore the SHA-256 of the full ciphertext string — differs every
		// time. This documents that re-encrypting the same logical payload yields
		// a new content hash (relevant for any dedup keyed on this hash).
		const a = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		const b = await AvsEncryption.encryptObject({ x: 1 }, TEST_KEY);
		const hashA = await AvsEncryption.computePayloadHash(a);
		const hashB = await AvsEncryption.computePayloadHash(b);
		expect(a).not.toBe(b);
		expect(hashA).not.toBe(hashB);
	});
});
