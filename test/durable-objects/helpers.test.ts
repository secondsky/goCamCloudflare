import { describe, it, expect } from 'vitest';
import {
	isValidStep,
	getStateMap,
	SESSION_STATE_IN_PROGRESS,
	SESSION_STATE_SUCCESS,
	SESSION_STATE_FAILED,
	SESSION_STATE_LINK_EXPIRED,
	SESSION_STATE_LINK_ALREADY_USED,
} from '../../src/durable-objects/verification-session';

describe('isValidStep', () => {
	it('accepts valid steps 1-7', () => {
		for (let i = 1; i <= 7; i++) {
			expect(isValidStep(i)).toBe(true);
		}
	});
	it('rejects 0', () => { expect(isValidStep(0)).toBe(false); });
	it('rejects 8', () => { expect(isValidStep(8)).toBe(false); });
	it('rejects negative', () => { expect(isValidStep(-1)).toBe(false); });
	it('rejects NaN', () => { expect(isValidStep(NaN)).toBe(false); });
});

describe('getStateMap', () => {
	it('returns all 5 session states', () => {
		const map = getStateMap();
		expect(map[SESSION_STATE_IN_PROGRESS]).toBe('inProgress');
		expect(map[SESSION_STATE_SUCCESS]).toBe('success');
		expect(map[SESSION_STATE_FAILED]).toBe('fail');
		expect(map[SESSION_STATE_LINK_EXPIRED]).toBe('expired');
		expect(map[SESSION_STATE_LINK_ALREADY_USED]).toBe('alreadyUsed');
	});
});
