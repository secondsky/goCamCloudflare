import { describe, it, expect } from 'vitest';
import { renderTokenEmbedCheck } from '../../src/templates/token-embed-check';
import type { EmbedCheckOptions } from '../../src/templates/token-embed-check';

/**
 * Extracts the JSON content embedded inside
 * `<script id="app-data" type="application/json">...</script>`.
 * renderTokenEmbedCheck serializes options.js directly (no renderBase) with
 * the same `<`→`\u003c`, U+2028, U+2029 transform, so JSON.parse yields an
 * object whose keys are isAgeVerified / verificationPayload.
 */
function extractAppDataJson(html: string): string {
	const match = html.match(/type="application\/json">([\s\S]*?)<\/script>/);
	if (!match || match[1] === undefined) {
		throw new Error('app-data script block not found');
	}
	return match[1];
}

function baseOptions(): EmbedCheckOptions {
	return {
		js: { isAgeVerified: false, verificationPayload: null },
		cacheBuster: 999,
	};
}

describe('renderTokenEmbedCheck', () => {
	describe('standalone document structure', () => {
		it('emits a standalone HTML document (DOCTYPE + own <html>) without renderBase chrome', () => {
			const html = renderTokenEmbedCheck(baseOptions());

			// Standalone doc markers.
			expect(html.startsWith('<!DOCTYPE HTML>')).toBe(true);
			expect(html).toContain('<html lang="en" xml:lang="en">');
			// renderBase injects a <title>Go.cam demo</title> and viewport meta;
			// the standalone embed-check page does NOT. Use that as a negative
			// signal that renderBase was bypassed.
			expect(html).not.toContain('<title>Go.cam demo</title>');
		});
	});

	describe('app-data JSON integrity', () => {
		it('reflects isAgeVerified:true at the top level of the app-data block', () => {
			const opts = baseOptions();
			opts.js.isAgeVerified = true;
			opts.js.verificationPayload = 'payload-abc';
			const html = renderTokenEmbedCheck(opts);

			const parsed = JSON.parse(extractAppDataJson(html));
			expect(parsed.isAgeVerified).toBe(true);
			expect(parsed.verificationPayload).toBe('payload-abc');
		});

		it('reflects isAgeVerified:false with a null verificationPayload', () => {
			const opts = baseOptions();
			opts.js.isAgeVerified = false;
			opts.js.verificationPayload = null;
			const html = renderTokenEmbedCheck(opts);

			const parsed = JSON.parse(extractAppDataJson(html));
			expect(parsed.isAgeVerified).toBe(false);
			expect(parsed.verificationPayload).toBeNull();
		});
	});

	describe('XSS prevention (security-critical)', () => {
		it('escapes a `</script>` payload in verificationPayload', () => {
			const opts = baseOptions();
			opts.js.verificationPayload = '</script><script>alert(1)</script>';
			const html = renderTokenEmbedCheck(opts);

			const payload = extractAppDataJson(html);
			expect(payload).not.toContain('</script>');
			expect(payload).toContain('\\u003c');
			// And the value still round-trips to the original string.
			const parsed = JSON.parse(payload);
			expect(parsed.verificationPayload).toBe(
				'</script><script>alert(1)</script>'
			);
		});

		it('escapes U+2028 / U+2029 in verificationPayload', () => {
			const opts = baseOptions();
			opts.js.verificationPayload = 'a\u2028b\u2029c';
			const html = renderTokenEmbedCheck(opts);

			const payload = extractAppDataJson(html);
			expect(payload).toContain('\\u2028');
			expect(payload).toContain('\\u2029');
			expect(payload).not.toContain('\u2028');
			expect(payload).not.toContain('\u2029');
		});
	});

	describe('cacheBuster interpolation', () => {
		it('appends cacheBuster to the avsFactoryIframeCheck.js script src', () => {
			const opts = baseOptions();
			opts.cacheBuster = 31415;
			const html = renderTokenEmbedCheck(opts);

			expect(html).toContain(
				'/static/js/app/avsFactoryIframeCheck.js?31415'
			);
		});
	});
});
