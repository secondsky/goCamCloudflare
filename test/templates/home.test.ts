import { describe, it, expect } from 'vitest';
import { renderHome } from '../../src/templates/home';
import type { HomeTemplateOptions } from '../../src/templates/home';

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

function baseOptions(): HomeTemplateOptions {
	return {
		js: { onDocumentReady: 'home' },
		cacheBuster: 42,
	};
}

describe('renderHome', () => {
	describe('app-data JSON integrity', () => {
		it('serializes onDocumentReady at the top level of the app-data block', () => {
			const opts = baseOptions();
			opts.js.onDocumentReady = 'initHome';
			const html = renderHome(opts);

			const parsed = JSON.parse(extractAppDataJson(html));
			expect(parsed.onDocumentReady).toBe('initHome');
		});
	});

	describe('XSS prevention in nodeEnv (HTML element context, escapeHtml)', () => {
		it('escapes a `<img src=x onerror=alert(1)>` payload via escapeHtml', () => {
			const opts = baseOptions();
			opts.nodeEnv = '<img src=x onerror=alert(1)>';
			const html = renderHome(opts);

			// The escaped form must be present in the "Node env:" small element.
			expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
			// The raw tag form must not appear (it would be a live img element).
			expect(html).not.toContain('<img src=x onerror=alert(1)>');
		});

		it('escapes ampersands, quotes, and angle brackets together', () => {
			const opts = baseOptions();
			opts.nodeEnv = `<a href="x" title='y'>&</a>`;
			const html = renderHome(opts);

			expect(html).toContain('&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
			expect(html).not.toContain('<a href="x" title=\'y\'>&</a>');
		});

		it('renders a benign nodeEnv value verbatim (no false positives)', () => {
			const opts = baseOptions();
			opts.nodeEnv = 'staging';
			const html = renderHome(opts);

			expect(html).toContain('Node env: staging');
		});
	});

	describe('nodeEnv default', () => {
		it("defaults to 'production' when nodeEnv is omitted", () => {
			const opts = baseOptions();
			// nodeEnv deliberately unset.
			const html = renderHome(opts);

			expect(html).toContain('Node env: production');
		});
	});

	describe('cacheBuster interpolation', () => {
		it('appends cacheBuster to common.js and avsFactoryIframeSdk.js script srcs', () => {
			const opts = baseOptions();
			opts.cacheBuster = 777;
			const html = renderHome(opts);

			expect(html).toContain('/static/js/app/common.js?777');
			expect(html).toContain('/static/js/app/avsFactoryIframeSdk.js?777');
		});
	});

	describe('XSS prevention in app-data block (onDocumentReady)', () => {
		it('escapes a `</script>` payload in onDocumentReady', () => {
			const opts = baseOptions();
			opts.js.onDocumentReady = '</script><script>alert(1)</script>';
			const html = renderHome(opts);

			const payload = extractAppDataJson(html);
			expect(payload).not.toContain('</script>');
			expect(payload).toContain('\\u003c');
		});
	});
});
