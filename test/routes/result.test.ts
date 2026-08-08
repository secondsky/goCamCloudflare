import { describe, it, expect } from 'vitest';
import { tokenIsValid } from '../../src/routes/result';

describe('tokenIsValid', () => {
	it('returns true when token matches the stored key', () => {
		expect(tokenIsValid('abc123', 'abc123')).toBe(true);
	});

	it('returns false when token does not match', () => {
		expect(tokenIsValid('abc123', 'wrong')).toBe(false);
	});

	it('returns false when stored key is undefined', () => {
		expect(tokenIsValid('abc123', undefined)).toBe(false);
	});

	it('returns false when token is empty', () => {
		expect(tokenIsValid('', 'abc123')).toBe(false);
	});
});
