import { describe, it, expect } from 'vitest';
import { renderTokenError } from '../../src/templates/token-error';

// escapeHtml is private (not exported), so we test it indirectly through
// renderTokenError. The error message lands inside
//   <h2 class="introText" id="errorMessageAdditionalTextArea"> {code} : {msg} </h2>
// The base template legitimately contains <script> tags in <head>, so the
// XSS test must scope its assertions to the error message area.

describe('renderTokenError HTML escaping', () => {
	it('escapes ampersands in the error message', () => {
		const out = renderTokenError(100, 'a&b');
		expect(out).toContain('a&amp;b');
		// No raw "a&b" sequence in the error text area.
		expect(out).not.toContain('>a&b<');
	});

	it('escapes angle brackets in an XSS payload', () => {
		const out = renderTokenError(100, '<script>alert(1)</script>');
		// Escaped form is present.
		expect(out).toContain('&lt;script&gt;');
		// The body of the payload is still visible as text.
		expect(out).toContain('alert(1)');
		// Within the error message <h2>, no raw <script> tag appears. The
		// closing tag of the h2 is the first "<" after the payload text, so
		// the unescaped form "<script>alert(1)</script>" must not appear.
		expect(out).not.toContain('<script>alert(1)</script>');
	});

	it('escapes double quotes', () => {
		const out = renderTokenError(100, 'say "hello"');
		expect(out).toContain('&quot;hello&quot;');
	});

	it('escapes single quotes', () => {
		const out = renderTokenError(100, "it's");
		expect(out).toContain('it&#39;s');
	});

	it('renders the numeric error code alongside the message', () => {
		const out = renderTokenError(30007, 'error');
		expect(out).toContain('30007 : error');
	});
});
