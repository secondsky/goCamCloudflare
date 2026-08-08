/**
 * Random string generation using Web Crypto API.
 * Uses hex encoding for URL-safe output (no +, /, = characters).
 */
export class AvsRandom {

	static generateRandomString(length = 16): string {
		// Generate enough random bytes (2 hex chars per byte)
		const bytes = crypto.getRandomValues(new Uint8Array(Math.ceil(length / 2)));
		return Array.from(bytes, b => b.toString(16).padStart(2, '0'))
			.join('')
			.slice(0, length);
	}
}
