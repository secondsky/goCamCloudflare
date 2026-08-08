/**
 * Cryptographic utilities: HKDF key derivation + constant-time comparison.
 * Uses Web Crypto API (no Node dependencies).
 */

/**
 * Derive a purpose-bound subkey from a master passphrase using HKDF-SHA256.
 * Different `context` strings produce cryptographically independent keys,
 * enabling key separation (one derived key for AES, another for HMAC).
 */
export async function hkdfDerive(
	masterKey: string,
	context: string,
	length: number,
): Promise<Uint8Array> {
	const encoder = new TextEncoder();
	const baseKey = await crypto.subtle.importKey(
		'raw',
		encoder.encode(masterKey),
		'HKDF',
		false,
		['deriveBits'],
	);
	const bits = await crypto.subtle.deriveBits(
		{
			name: 'HKDF',
			hash: 'SHA-256',
			salt: encoder.encode('gocam-hkdf-salt-v1'),
			info: encoder.encode(context),
		},
		baseKey,
		length * 8,
	);
	return new Uint8Array(bits);
}

/**
 * Compare two strings in constant time (no early-exit on first mismatch).
 * Uses a manual XOR-accumulate so it does not depend on crypto.subtle.verify
 * (which would require importing an HMAC key).
 */
export function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	const encoder = new TextEncoder();
	const aBytes = encoder.encode(a);
	const bBytes = encoder.encode(b);
	let diff = 0;
	for (let i = 0; i < aBytes.byteLength; i++) {
		diff |= aBytes[i] ^ bBytes[i];
	}
	return diff === 0;
}
