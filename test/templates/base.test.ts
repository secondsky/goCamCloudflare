import { describe, it, expect } from 'vitest';
import { renderBase } from '../../src/templates/base';

/**
 * Extracts the JSON content embedded inside
 * `<script id="app-data" type="application/json">...</script>`.
 */
function extractAppDataJson(html: string): string {
	const match = html.match(/type="application\/json">([\s\S]*?)<\/script>/);
	if (!match || match[1] === undefined) {
		throw new Error('app-data script block not found');
	}
	return match[1];
}

describe('renderBase', () => {
	describe('XSS prevention (security-critical)', () => {
		it('escapes `<` to `\\u003c` so `</script>` cannot break out of the block', () => {
			const html = renderBase({
				content: '',
				js: { html: '</script><script>alert(1)</script>' },
			});

			// The raw `</script>` payload must never appear verbatim — that
			// would let an attacker terminate the app-data block and inject
			// markup. Pull just the contents between the script tags.
			const payload = extractAppDataJson(html);
			expect(payload).not.toContain('</script>');
			expect(payload).toContain('\\u003c');
			expect(payload).not.toContain('<');
		});

		it('escapes the U+2028 line separator to the literal `\\u2028` sequence', () => {
			const html = renderBase({
				content: '',
				js: { value: 'before\u2028after' },
			});

			const payload = extractAppDataJson(html);
			expect(payload).toContain('\\u2028');
			expect(payload).not.toContain('\u2028');
		});

		it('escapes the U+2029 paragraph separator to the literal `\\u2029` sequence', () => {
			const html = renderBase({
				content: '',
				js: { value: 'before\u2029after' },
			});

			const payload = extractAppDataJson(html);
			expect(payload).toContain('\\u2029');
			expect(payload).not.toContain('\u2029');
		});
	});

	describe('JSON integrity', () => {
		it('round-trips normal data through the app-data block', () => {
			const data = { token: 'abc', count: 42 };
			const html = renderBase({ content: '', js: data });

			const payload = extractAppDataJson(html);
			expect(JSON.parse(payload)).toEqual(data);
		});

		it('embeds `{}` when js is omitted', () => {
			const html = renderBase({ content: 'hello' });
			expect(extractAppDataJson(html)).toBe('{}');
		});
	});

	describe('content rendering', () => {
		it('places the content string in the body', () => {
			const html = renderBase({ content: '<div id="test">Hello</div>' });
			expect(html).toContain('<div id="test">Hello</div>');
		});
	});
});
