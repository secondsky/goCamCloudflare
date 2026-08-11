/**
 * Color validation and sanitization for partner-submitted color config.
 *
 * Partners submit 5 hex color values via the /getVerificationPayloadAndUrl
 * form. These flow into an encrypted payload, are decrypted by the token
 * route, and are passed to the template as `partnerColorConfig`. To prevent
 * XSS (e.g. `javascript:alert(1)` submitted as a "color"), this module
 * provides two layers:
 *
 *   1. `isValidHexColor` — used at input time (src/routes/index.ts) to
 *      reject malformed colors with a clear per-field error.
 *   2. `sanitizeColorConfig` — used at render time (src/routes/token.ts)
 *      as defense-in-depth: if an old/pre-validation payload is decrypted,
 *      invalid/missing colors are replaced with safe defaults before
 *      reaching the template.
 *
 * The accepted format is 3-digit or 6-digit hex, with an optional leading
 * `#`, case-insensitive. Surrounding whitespace is trimmed before matching.
 * 4-digit, 8-digit (alpha), and non-hex-character values are rejected.
 */

const HEX_COLOR_RE = /^#?(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})$/;

/**
 * Returns true iff `value` is a string that, after trimming surrounding
 * whitespace, is a valid 3- or 6-digit hex color with an optional `#`.
 *
 * Accepts: `'#ffffff'`, `'#FFFFFF'`, `'ffffff'`, `'#fff'`, `'#FFF'`,
 * `'fff'`, `'  #ffffff  '` (trimmed).
 * Rejects: `'javascript:alert(1)'`, `'not-a-color'`, `'#fff0'` (4-digit),
 * `'#gggggg'`, `''`, `'  '`, numbers, objects, arrays, null, undefined.
 */
export function isValidHexColor(value: unknown): boolean {
	if (typeof value !== 'string') return false;
	return HEX_COLOR_RE.test(value.trim());
}

/**
 * The default partner color config — the form defaults emitted by
 * src/templates/home.ts (`<input type="color" value="...">`). Used as
 * the fallback for any invalid/missing color during sanitization.
 */
export const DEFAULT_COLOR_CONFIG = {
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

/**
 * Defensively walk the nested color config shape and return a full, valid
 * config. Each of the 5 leaf colors is validated with `isValidHexColor`;
 * any invalid or missing value is replaced with the corresponding default
 * from `DEFAULT_COLOR_CONFIG`. Returns a fresh object and never mutates
 * the input.
 *
 * Given garbage (null, non-object, missing `body`, partial `button`),
 * returns the full default config.
 */
export function sanitizeColorConfig(config: unknown): typeof DEFAULT_COLOR_CONFIG {
	const d = DEFAULT_COLOR_CONFIG;
	if (!config || typeof config !== 'object' || Array.isArray(config)) {
		// Spread defaults so callers always get a fresh object.
		return { body: { background: d.body.background, foreground: d.body.foreground, button: { ...d.body.button } } };
	}

	const c = config as Record<string, any>;
	const body = (c && typeof c.body === 'object' && c.body !== null && !Array.isArray(c.body)) ? c.body : {};
	const button = (body && typeof body.button === 'object' && body.button !== null && !Array.isArray(body.button)) ? body.button : {};

	const pick = (v: unknown, def: string): string => (isValidHexColor(v) ? (v as string).trim() : def);

	return {
		body: {
			background:             pick(body.background,             d.body.background),
			foreground:             pick(body.foreground,             d.body.foreground),
			button: {
				background:             pick(button.background,             d.body.button.background),
				foreground:             pick(button.foreground,             d.body.button.foreground),
				foregroundCallToAction: pick(button.foregroundCallToAction, d.body.button.foregroundCallToAction),
			},
		},
	};
}
