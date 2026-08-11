import { describe, it, expect } from 'vitest';
import { renderTokenIndex } from '../../src/templates/token-index';
import type { TokenIndexOptions } from '../../src/templates/token-index';

/**
 * Extracts the JSON content embedded inside
 * `<script id="app-data" type="application/json">...</script>`.
 * The `js` object is serialized at the TOP LEVEL of this JSON by renderBase,
 * so JSON.parse yields an object whose keys are the fields of `options.js`.
 */
function extractAppDataJson(html: string): string {
	const match = html.match(/type="application\/json">([\s\S]*?)<\/script>/);
	if (!match || match[1] === undefined) {
		throw new Error('app-data script block not found');
	}
	return match[1];
}

/**
 * Minimal valid options. Tests override individual fields. The defaults are
 * deliberately benign so a test that forgets to set a field still produces
 * a renderable page (no NaN/undefined leaking into the JSON).
 */
function baseOptions(): TokenIndexOptions {
	return {
		js: {
			onDocumentReady: 'avs',
			token: 'tok-abc',
			isLiveness: true,
			showDetectedAgeNumber: false,
			verificationTypeList: ['selfie'],
			verificationVersion: 2,
			d: 'device-1',
			sessionId: 'sess-1',
			partnerColorConfig: { background: '#fff' },
			ipCountry: 'US',
			deviceInfo: { platform: 'desktop' },
			countryAgeMajority: { US: 21 },
		},
		debug: false,
		cacheBuster: 12345,
	};
}

describe('renderTokenIndex', () => {
	describe('app-data JSON integrity', () => {
		it('serializes all options.js fields at the top level (round-trip)', () => {
			const opts = baseOptions();
			const html = renderTokenIndex(opts);

			const parsed = JSON.parse(extractAppDataJson(html));
			// Every top-level key from options.js is present and intact.
			expect(parsed.token).toBe(opts.js.token);
			expect(parsed.isLiveness).toBe(opts.js.isLiveness);
			expect(parsed.showDetectedAgeNumber).toBe(opts.js.showDetectedAgeNumber);
			expect(parsed.verificationVersion).toBe(opts.js.verificationVersion);
			expect(parsed.d).toBe(opts.js.d);
			expect(parsed.sessionId).toBe(opts.js.sessionId);
			expect(parsed.ipCountry).toBe(opts.js.ipCountry);
			expect(parsed.countryAgeMajority).toEqual(opts.js.countryAgeMajority);
		});

		it('round-trips verificationTypeList as an array', () => {
			const opts = baseOptions();
			opts.js.verificationTypeList = ['selfie', 'scanId'];
			const html = renderTokenIndex(opts);

			const parsed = JSON.parse(extractAppDataJson(html));
			expect(parsed.verificationTypeList).toEqual(['selfie', 'scanId']);
			expect(Array.isArray(parsed.verificationTypeList)).toBe(true);
		});

		it('round-trips nested partnerColorConfig / deviceInfo objects', () => {
			const opts = baseOptions();
			opts.js.partnerColorConfig = { button: { bg: '#9acd1f', fg: '#ffffff' } };
			opts.js.deviceInfo = { ua: 'Mozilla', os: 'macOS' };
			const html = renderTokenIndex(opts);

			const parsed = JSON.parse(extractAppDataJson(html));
			expect(parsed.partnerColorConfig).toEqual({
				button: { bg: '#9acd1f', fg: '#ffffff' },
			});
			expect(parsed.deviceInfo).toEqual({ ua: 'Mozilla', os: 'macOS' });
		});
	});

	describe('XSS prevention (security-critical)', () => {
		it('escapes a `</script>` payload in `token` so it cannot break out of the app-data block', () => {
			const opts = baseOptions();
			opts.js.token = '</script><script>alert(1)</script>';
			const html = renderTokenIndex(opts);

			const payload = extractAppDataJson(html);
			// Raw closing tag must never appear inside the JSON block.
			expect(payload).not.toContain('</script>');
			// The `<` is escaped to the literal backslash-u-003c sequence.
			expect(payload).toContain('\\u003c');
		});

		it('escapes `<` inside a nested malicious string in partnerColorConfig', () => {
			const opts = baseOptions();
			opts.js.partnerColorConfig = { evil: '</script><img src=x onerror=alert(1)>' };
			const html = renderTokenIndex(opts);

			const payload = extractAppDataJson(html);
			expect(payload).not.toContain('</script>');
			expect(payload).toContain('\\u003c');
			// And the nested object still round-trips after the escape.
			const parsed = JSON.parse(payload);
			expect(parsed.partnerColorConfig.evil).toBe(
				'</script><img src=x onerror=alert(1)>'
			);
		});

		it('escapes U+2028 (line separator) to the literal `\\u2028` sequence in sessionId', () => {
			const opts = baseOptions();
			opts.js.sessionId = 'before\u2028after';
			const html = renderTokenIndex(opts);

			const payload = extractAppDataJson(html);
			expect(payload).toContain('\\u2028');
			expect(payload).not.toContain('\u2028');
		});

		it('escapes U+2029 (paragraph separator) to the literal `\\u2029` sequence in ipCountry', () => {
			const opts = baseOptions();
			opts.js.ipCountry = 'before\u2029after';
			const html = renderTokenIndex(opts);

			const payload = extractAppDataJson(html);
			expect(payload).toContain('\\u2029');
			expect(payload).not.toContain('\u2029');
		});

		it('escapes U+2028/U+2029 inside deviceInfo (nested object)', () => {
			const opts = baseOptions();
			opts.js.deviceInfo = { a: 'x\u2028y', b: 'x\u2029y' };
			const html = renderTokenIndex(opts);

			const payload = extractAppDataJson(html);
			expect(payload).toContain('\\u2028');
			expect(payload).toContain('\\u2029');
			expect(payload).not.toContain('\u2028');
			expect(payload).not.toContain('\u2029');
		});
	});

	describe('debug section', () => {
		it('omits the debug section when debug is false', () => {
			const opts = baseOptions();
			opts.debug = false;
			const html = renderTokenIndex(opts);

			expect(html).not.toContain('id="debugArea"');
			expect(html).not.toContain('debugCloseButton');
		});

		it('renders the debug section when debug is true', () => {
			const opts = baseOptions();
			opts.debug = true;
			const html = renderTokenIndex(opts);

			expect(html).toContain('id="debugArea"');
			expect(html).toContain('debugCloseButton');
		});
	});

	describe('cacheBuster interpolation', () => {
		it('appends cacheBuster to the avs.js / avsFactory.js / common.js script srcs', () => {
			const opts = baseOptions();
			opts.cacheBuster = 98765;
			const html = renderTokenIndex(opts);

			expect(html).toContain('/static/js/app/avs.js?98765');
			expect(html).toContain('/static/js/app/avsFactory.js?98765');
			expect(html).toContain('/static/js/app/common.js?98765');
		});
	});
});
