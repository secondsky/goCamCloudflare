import { describe, it, expect } from 'vitest';
import { AvsResponse } from '../../src/lib/response';

describe('AvsResponse', () => {
	describe('successResponse', () => {
		it('spreads data and sets success: 1', () => {
			expect(AvsResponse.successResponse({ token: 'abc' })).toEqual({
				content: { token: 'abc', success: 1 },
			});
		});

		it('returns { content: { success: 1 } } when called with no args', () => {
			expect(AvsResponse.successResponse()).toEqual({
				content: { success: 1 },
			});
		});

		it('does not mutate the input data object', () => {
			const input = { token: 'abc', nested: { a: 1 } };
			AvsResponse.successResponse(input);
			expect(input).toEqual({ token: 'abc', nested: { a: 1 } });
			expect(input).not.toHaveProperty('success');
		});
	});

	describe('errorResponse', () => {
		it('returns the given code and msg in an error envelope', () => {
			expect(AvsResponse.errorResponse(30001, 'bad request')).toEqual({
				error: { code: 30001, msg: 'bad request' },
			});
		});
	});
});
