/**
 * Safely parse an integer from unknown input.
 *
 * Returns `defaultValue` if the input is not a clean integer. Unlike
 * `parseInt`, this rejects trailing garbage like "3abc" or "3<script>"
 * (parseInt would silently return 3). Also guards against `NaN`/`Infinity`
 * propagation.
 *
 * Accepts finite numbers (truncated with Math.trunc) and strings that are
 * optionally signed digit sequences, optionally surrounded by whitespace.
 */
export function safeParseInt(value: unknown, defaultValue: number = 0): number {
	if (typeof value === 'number') {
		return Number.isFinite(value) ? Math.trunc(value) : defaultValue;
	}
	if (typeof value !== 'string') return defaultValue;
	const trimmed = value.trim();
	if (!/^-?\d+$/.test(trimmed)) return defaultValue;
	const n = parseInt(trimmed, 10);
	return Number.isFinite(n) ? n : defaultValue;
}
