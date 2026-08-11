import { describe, it, expect } from 'vitest';
import { isValidHexColor, sanitizeColorConfig, DEFAULT_COLOR_CONFIG } from '../../src/lib/color';

describe('isValidHexColor', () => {
	describe('accepts valid hex colors', () => {
		it('accepts 6-digit lowercase with #', () => {
			expect(isValidHexColor('#ffffff')).toBe(true);
		});
		it('accepts 6-digit uppercase with #', () => {
			expect(isValidHexColor('#FFFFFF')).toBe(true);
		});
		it('accepts 6-digit mixed case with #', () => {
			expect(isValidHexColor('#FfAa00')).toBe(true);
		});
		it('accepts 6-digit without #', () => {
			expect(isValidHexColor('ffffff')).toBe(true);
		});
		it('accepts 3-digit with # (lowercase)', () => {
			expect(isValidHexColor('#fff')).toBe(true);
		});
		it('accepts 3-digit with # (uppercase)', () => {
			expect(isValidHexColor('#FFF')).toBe(true);
		});
		it('accepts 3-digit without #', () => {
			expect(isValidHexColor('fff')).toBe(true);
		});
	});

	describe('trims surrounding whitespace before validating', () => {
		it('accepts "  #ffffff  " (whitespace around valid hex)', () => {
			expect(isValidHexColor('  #ffffff  ')).toBe(true);
		});
		it('accepts "\\t#fff\\n" (tabs/newlines around valid hex)', () => {
			expect(isValidHexColor('\t#fff\n')).toBe(true);
		});
	});

	describe('rejects invalid inputs', () => {
		it('rejects javascript: URL payload', () => {
			expect(isValidHexColor('javascript:alert(1)')).toBe(false);
		});
		it('rejects arbitrary string', () => {
			expect(isValidHexColor('not-a-color')).toBe(false);
		});
		it('rejects 4-digit hex', () => {
			expect(isValidHexColor('#fff0')).toBe(false);
		});
		it('rejects 8-digit hex (with alpha)', () => {
			expect(isValidHexColor('#ffffff00')).toBe(false);
		});
		it('rejects non-hex chars in 6-digit slot', () => {
			expect(isValidHexColor('#gggggg')).toBe(false);
		});
		it('rejects empty string', () => {
			expect(isValidHexColor('')).toBe(false);
		});
		it('rejects whitespace-only string', () => {
			expect(isValidHexColor('  ')).toBe(false);
		});
		it('rejects a number', () => {
			expect(isValidHexColor(0xffffff)).toBe(false);
		});
		it('rejects a number 0', () => {
			expect(isValidHexColor(0)).toBe(false);
		});
		it('rejects an object', () => {
			expect(isValidHexColor({})).toBe(false);
		});
		it('rejects an array', () => {
			expect(isValidHexColor(['#ffffff'])).toBe(false);
		});
		it('rejects null', () => {
			expect(isValidHexColor(null)).toBe(false);
		});
		it('rejects undefined', () => {
			expect(isValidHexColor(undefined)).toBe(false);
		});
		it('rejects a boolean', () => {
			expect(isValidHexColor(true)).toBe(false);
		});
		it('rejects internal whitespace (not just leading/trailing)', () => {
			expect(isValidHexColor('#ff ffff')).toBe(false);
		});
	});
});

describe('DEFAULT_COLOR_CONFIG', () => {
	it('has the 5 expected defaults from home.ts form values', () => {
		expect(DEFAULT_COLOR_CONFIG).toEqual({
			body: {
				background: '#ffffff',
				foreground: '#000000',
				button: {
					background: '#9acd1f',
					foreground: '#ffffff',
					foregroundCallToAction: '#ffffff',
				},
			},
		});
	});
});

describe('sanitizeColorConfig', () => {
	it('returns a full default config given null', () => {
		expect(sanitizeColorConfig(null)).toEqual(DEFAULT_COLOR_CONFIG);
	});

	it('returns a full default config given undefined', () => {
		expect(sanitizeColorConfig(undefined)).toEqual(DEFAULT_COLOR_CONFIG);
	});

	it('returns a full default config given a non-object (string)', () => {
		expect(sanitizeColorConfig('garbage')).toEqual(DEFAULT_COLOR_CONFIG);
	});

	it('returns a full default config given a non-object (number)', () => {
		expect(sanitizeColorConfig(42)).toEqual(DEFAULT_COLOR_CONFIG);
	});

	it('returns a full default config given an array', () => {
		expect(sanitizeColorConfig(['#ffffff'])).toEqual(DEFAULT_COLOR_CONFIG);
	});

	it('returns a full default config given an object missing body', () => {
		expect(sanitizeColorConfig({ other: 'x' })).toEqual(DEFAULT_COLOR_CONFIG);
	});

	it('returns a full default config given body missing', () => {
		expect(sanitizeColorConfig({})).toEqual(DEFAULT_COLOR_CONFIG);
	});

	it('substitutes defaults for missing body.background but keeps valid foreground', () => {
		const input = {
			body: {
				foreground: '#123456',
				// background missing
			},
		};
		const out = sanitizeColorConfig(input);
		expect(out.body.background).toBe('#ffffff');
		expect(out.body.foreground).toBe('#123456');
		expect(out.body.button).toEqual(DEFAULT_COLOR_CONFIG.body.button);
	});

	it('substitutes defaults for missing button but keeps valid body colors', () => {
		const input = {
			body: {
				background: '#111111',
				foreground: '#222222',
			},
		};
		const out = sanitizeColorConfig(input);
		expect(out.body.background).toBe('#111111');
		expect(out.body.foreground).toBe('#222222');
		expect(out.body.button).toEqual(DEFAULT_COLOR_CONFIG.body.button);
	});

	it('substitutes defaults for partial button (missing foregroundCallToAction)', () => {
		const input = {
			body: {
				background: '#111111',
				foreground: '#222222',
				button: {
					background: '#333333',
					foreground: '#444444',
					// foregroundCallToAction missing
				},
			},
		};
		const out = sanitizeColorConfig(input);
		expect(out.body.button.background).toBe('#333333');
		expect(out.body.button.foreground).toBe('#444444');
		expect(out.body.button.foregroundCallToAction).toBe('#ffffff');
	});

	it('substitutes default for an invalid color (XSS payload) in one field, keeps others valid', () => {
		const input = {
			body: {
				background: 'javascript:alert(1)',
				foreground: '#000000',
				button: {
					background: '#9acd1f',
					foreground: '#ffffff',
					foregroundCallToAction: '#ffffff',
				},
			},
		};
		const out = sanitizeColorConfig(input);
		// Invalid → default
		expect(out.body.background).toBe('#ffffff');
		// Others preserved
		expect(out.body.foreground).toBe('#000000');
		expect(out.body.button.background).toBe('#9acd1f');
		expect(out.body.button.foreground).toBe('#ffffff');
		expect(out.body.button.foregroundCallToAction).toBe('#ffffff');
	});

	it('substitutes defaults for every field when all are invalid', () => {
		const input = {
			body: {
				background: '<script>',
				foreground: 'not-a-color',
				button: {
					background: '#fff0', // 4-digit, invalid
					foreground: '#gggggg',
					foregroundCallToAction: 'javascript:alert(1)',
				},
			},
		};
		expect(sanitizeColorConfig(input)).toEqual(DEFAULT_COLOR_CONFIG);
	});

	it('accepts 3-digit hex and keeps it as-is (does not canonicalize)', () => {
		const input = {
			body: {
				background: '#fff',
				foreground: '#000',
				button: {
					background: '#0f0',
					foreground: '#00f',
					foregroundCallToAction: '#f00',
				},
			},
		};
		const out = sanitizeColorConfig(input);
		expect(out).toEqual({
			body: {
				background: '#fff',
				foreground: '#000',
				button: {
					background: '#0f0',
					foreground: '#00f',
					foregroundCallToAction: '#f00',
				},
			},
		});
	});

	it('accepts hex without leading # and keeps it as-is', () => {
		const input = {
			body: {
				background: 'ffffff',
				foreground: '000000',
				button: {
					background: '9acd1f',
					foreground: 'ffffff',
					foregroundCallToAction: 'ffffff',
				},
			},
		};
		const out = sanitizeColorConfig(input);
		expect(out.body.background).toBe('ffffff');
		expect(out.body.button.background).toBe('9acd1f');
	});

	it('returns a full valid config unchanged', () => {
		const input = {
			body: {
				background: '#abcdef',
				foreground: '#012345',
				button: {
					background: '#6789ab',
					foreground: '#cdef01',
					foregroundCallToAction: '#234567',
				},
			},
		};
		expect(sanitizeColorConfig(input)).toEqual(input);
	});

	it('trims whitespace before validating (keeps trimmed value)', () => {
		const input = {
			body: {
				background: '  #ffffff  ',
				foreground: '#000000',
				button: {
					background: '#9acd1f',
					foreground: '#ffffff',
					foregroundCallToAction: '#ffffff',
				},
			},
		};
		const out = sanitizeColorConfig(input);
		expect(out.body.background).toBe('#ffffff');
	});

	it('returns a fresh object (does not mutate input)', () => {
		const input = {
			body: {
				background: '#ffffff',
				foreground: '#000000',
				button: {
					background: '#9acd1f',
					foreground: '#ffffff',
					foregroundCallToAction: '#ffffff',
				},
			},
		};
		const out = sanitizeColorConfig(input);
		expect(out).not.toBe(input);
		expect(out.body).not.toBe(input.body);
		expect(out.body.button).not.toBe(input.body.button);
	});

	it('does not mutate the input when substituting defaults', () => {
		const input = {
			body: {
				background: 'javascript:alert(1)',
				foreground: '#000000',
				button: {
					background: '#9acd1f',
					foreground: '#ffffff',
					foregroundCallToAction: '#ffffff',
				},
			},
		};
		const snapshot = JSON.parse(JSON.stringify(input));
		sanitizeColorConfig(input);
		expect(input).toEqual(snapshot);
	});
});
