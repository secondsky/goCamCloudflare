import { describe, it, expect } from 'vitest';
import { safeParseInt } from '../../src/lib/parse';

describe('safeParseInt', () => {
	it('parses a valid integer string', () => {
		expect(safeParseInt('42', 0)).toBe(42);
	});

	it('returns default for non-numeric', () => {
		expect(safeParseInt('abc', 0)).toBe(0);
	});

	it('returns default for NaN input', () => {
		expect(safeParseInt(NaN, 5)).toBe(5);
	});

	it('returns default for undefined', () => {
		expect(safeParseInt(undefined, 0)).toBe(0);
	});

	it('rejects trailing garbage', () => {
		expect(safeParseInt('3<script>', 0)).toBe(0);
	});

	it('parses negative integers', () => {
		expect(safeParseInt('-7', 0)).toBe(-7);
	});

	it('trims surrounding whitespace', () => {
		expect(safeParseInt('  42  ', 0)).toBe(42);
	});

	it('returns default for empty string', () => {
		expect(safeParseInt('', 9)).toBe(9);
	});

	it('returns default for null', () => {
		expect(safeParseInt(null, 9)).toBe(9);
	});

	it('truncates finite numbers', () => {
		expect(safeParseInt(3.9, 0)).toBe(3);
	});

	it('returns default for non-finite numbers (Infinity)', () => {
		expect(safeParseInt(Infinity, 2)).toBe(2);
	});
});
