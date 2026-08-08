/**
 * AES-256-GCM encryption/decryption using the Web Crypto API.
 * All methods are async (Web Crypto is promise-based).
 *
 * AES-GCM provides authenticated encryption: the 16-byte GCM tag appended to
 * the ciphertext is verified on decrypt, so any tampering is rejected. (The
 * previous AES-CBC implementation had no MAC, leaving ciphertexts malleable.)
 */

import type { DecryptedPayload } from './types';

export class AvsEncryption {

	private static encoder = new TextEncoder();
	private static decoder = new TextDecoder();
	private static keyCache = new Map<string, CryptoKey>();

	/**
	 * Import a raw key (HKDF-derived bytes) as a CryptoKey for AES-GCM.
	 * Caches the CryptoKey per key bytes to avoid re-importing.
	 */
	private static async importKey(keyBytes: Uint8Array): Promise<CryptoKey> {
		// Cache by a lightweight serialization of the key bytes to avoid re-importing.
		const cacheKey = Array.from(keyBytes).join(',');
		let cached = AvsEncryption.keyCache.get(cacheKey);
		if (cached) return cached;
		const key = await crypto.subtle.importKey(
			'raw',
			keyBytes,
			{ name: 'AES-GCM' },
			false,
			['encrypt', 'decrypt']
		);
		AvsEncryption.keyCache.set(cacheKey, key);
		return key;
	}

	/**
	 * Convert a hex string to a Uint8Array.
	 */
	private static hexToBytes(hex: string): Uint8Array {
		const bytes = new Uint8Array(hex.length / 2);
		for (let i = 0; i < hex.length; i += 2) {
			bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
		}
		return bytes;
	}

	/**
	 * Convert a Uint8Array to a hex string.
	 */
	private static bytesToHex(bytes: Uint8Array): string {
		return Array.from(bytes)
			.map(b => b.toString(16).padStart(2, '0'))
			.join('');
	}

	/**
	 * Encrypt an object to a string in the format: ivHex|:encryptedHex
	 * Compatible with the original Node.js implementation.
	 */
	static async encryptObject(object: object, keyBytes: Uint8Array): Promise<string> {
		const key = await AvsEncryption.importKey(keyBytes);
		const iv = crypto.getRandomValues(new Uint8Array(12));

		const plaintext = AvsEncryption.encoder.encode(JSON.stringify(object));

		const encrypted = await crypto.subtle.encrypt(
			{ name: 'AES-GCM', iv },
			key,
			plaintext
		);

		const ivHex = AvsEncryption.bytesToHex(iv);
		const encryptedHex = AvsEncryption.bytesToHex(new Uint8Array(encrypted));

		return ivHex + '|:' + encryptedHex;
	}

	/**
	 * Decrypt a string in the format: ivHex|:encryptedHex (with '|' as separator)
	 * The original Node.js code splits on ':' —
	 * iv part ends with '|', encrypted part follows after ':'
	 * So split(':') gives [ivHex + '|', encryptedHex]
	 * We trim the trailing '|' from the iv part.
	 */
	static async decryptString(encryptedString: string, keyBytes: Uint8Array): Promise<DecryptedPayload> {
		const key = await AvsEncryption.importKey(keyBytes);

		const separatorIndex = encryptedString.indexOf(':');
		// iv part is everything before ':', minus the trailing '|'
		const ivHex = encryptedString.substring(0, separatorIndex).replace(/\|$/, '');
		const encryptedHex = encryptedString.substring(separatorIndex + 1);

		const iv = AvsEncryption.hexToBytes(ivHex);
		const encryptedData = AvsEncryption.hexToBytes(encryptedHex);

		const decrypted = await crypto.subtle.decrypt(
			{ name: 'AES-GCM', iv },
			key,
			encryptedData
		);

		return JSON.parse(AvsEncryption.decoder.decode(decrypted));
	}

	/**
	 * Compute a SHA-256 hash of the payload ciphertext.
	 *
	 * This is a content-addressable identifier — the same ciphertext always
	 * produces the same hash, regardless of the random IV embedded in it.
	 * Used for DO routing, dedup, and session identity. (Previously this was
	 * computed as `payload.substring(0, 64)`, which is the IV prefix and
	 * therefore changed every time the same payload was re-encrypted.)
	 */
	static async computePayloadHash(ciphertext: string): Promise<string> {
		const data = AvsEncryption.encoder.encode(ciphertext);
		const hashBuffer = await crypto.subtle.digest('SHA-256', data);
		return AvsEncryption.bytesToHex(new Uint8Array(hashBuffer));
	}

	/**
	 * Base64 encode an object to a string.
	 */
	static base64EncodeObject(object: object): string {
		return btoa(JSON.stringify(object));
	}

	/**
	 * Base64 decode a string to a parsed object.
	 */
	static base64DecodeString(encodedString: string): any {
		return JSON.parse(atob(encodedString));
	}
}
