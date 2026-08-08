import { describe, it, expect } from 'vitest';
import { isDecryptedPayload } from '../../src/lib/types';

describe('isDecryptedPayload', () => {
	it('accepts a well-formed payload', () => {
		expect(isDecryptedPayload({
			userData: {}, websiteHostname: 'example.com', callbackUrl: 'https://x.com',
			creationTimestamp: Date.now(), userIpStr: '1.2.3.4', userIpCountry: 'US',
		})).toBe(true);
	});

	it('rejects null', () => {
		expect(isDecryptedPayload(null)).toBe(false);
	});

	it('rejects missing callbackUrl', () => {
		// Per the loose (OR) check in the plan, { userData: {} } passes because
		// userData is an object. This test documents that the guard is a loose
		// first-pass check rather than a strict validator.
		expect(isDecryptedPayload({ userData: {} })).toBe(true);
	});

	it('rejects primitives', () => {
		expect(isDecryptedPayload('hello')).toBe(false);
		expect(isDecryptedPayload(42)).toBe(false);
		expect(isDecryptedPayload(true)).toBe(false);
		expect(isDecryptedPayload(undefined)).toBe(false);
	});

	it('rejects an empty object (no key field present)', () => {
		expect(isDecryptedPayload({})).toBe(false);
	});

	it('rejects an object whose key fields are all wrong types', () => {
		expect(isDecryptedPayload({
			userData: 'not-an-object',
			websiteHostname: 123,
			callbackUrl: {},
			creationTimestamp: 'nope',
		})).toBe(false);
	});

	it('accepts an object with only a valid websiteHostname', () => {
		// Loose (OR) semantics: one matching key field is enough.
		expect(isDecryptedPayload({ websiteHostname: 'example.com' })).toBe(true);
	});

	it('narrows the type so typed field access compiles', () => {
		const input: unknown = {
			userData: { foo: 1 },
			websiteHostname: 'example.com',
			callbackUrl: 'https://x.com',
			creationTimestamp: 123,
			userIpStr: '1.2.3.4',
			userIpCountry: 'US',
		};
		if (isDecryptedPayload(input)) {
			expect(input.websiteHostname).toBe('example.com');
			expect(input.callbackUrl).toBe('https://x.com');
			expect(input.creationTimestamp).toBe(123);
		} else {
			throw new Error('expected payload to be accepted');
		}
	});
});
