import { describe, it, expect } from 'vitest';
import { AvsRandom } from '../../src/lib/random';

describe('AvsRandom.generateRandomString', () => {
	it('defaults to length 16', () => {
		expect(AvsRandom.generateRandomString()).toHaveLength(16);
	});

	it('honors a custom length', () => {
		expect(AvsRandom.generateRandomString(32)).toHaveLength(32);
	});

	it('produces hex-only output', () => {
		expect(AvsRandom.generateRandomString(64)).toMatch(/^[0-9a-f]+$/);
	});

	it('is non-deterministic', () => {
		const a = AvsRandom.generateRandomString();
		const b = AvsRandom.generateRandomString();
		expect(a).not.toBe(b);
	});

	it('returns an empty string for length 0', () => {
		expect(AvsRandom.generateRandomString(0)).toBe('');
	});

	it('returns exactly the requested odd length', () => {
		// Math.ceil(15 / 2) = 8 bytes -> 16 hex chars; slice must trim to 15.
		expect(AvsRandom.generateRandomString(15)).toHaveLength(15);
	});
});
