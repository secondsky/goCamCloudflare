/**
 * Validate that a callback URL is safe to fetch server-side.
 * Prevents SSRF by enforcing http(s) scheme and blocking private/loopback IPs.
 *
 * Note: this validates the hostname as written. For hostnames that resolve
 * dynamically, a DNS-rebinding attack is still theoretically possible.
 * A production deployment should pair this with a partner-host allowlist.
 */

const PRIVATE_IPV4_PATTERNS: RegExp[] = [
	/^0\./,                           // 0.0.0.0/8 ("this host" / SSRF bypass)
	/^10\./,                          // 10.0.0.0/8
	/^127\./,                         // 127.0.0.0/8
	/^169\.254\./,                    // 169.254.0.0/16 (link-local + cloud metadata)
	/^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
	/^192\.168\./,                    // 192.168.0.0/16
	/^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./, // 100.64.0.0/10 (CGNAT)
];

export type CallbackUrlResult = { ok: true } | { ok: false; reason: string };

export function isSafeCallbackUrl(urlStr: string): CallbackUrlResult {
	if (!urlStr || typeof urlStr !== 'string') {
		return { ok: false, reason: 'empty' };
	}

	let parsed: URL;
	try {
		parsed = new URL(urlStr);
	} catch {
		return { ok: false, reason: 'malformed' };
	}

	if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
		return { ok: false, reason: 'bad_scheme' };
	}

	const hostname = parsed.hostname.toLowerCase();

	// Reject localhost by name
	if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
		return { ok: false, reason: 'loopback' };
	}

	// IPv4 literal checks
	for (const pattern of PRIVATE_IPV4_PATTERNS) {
		if (pattern.test(hostname)) {
			return { ok: false, reason: 'private_range' };
		}
	}

	// IPv6 loopback / link-local / unique-local (case-insensitive — the
	// hostname is already lowercased above, but IPv6 literals from URL
	// parsing may retain original case inside the brackets).
	const v6 = hostname.toLowerCase();
	if (v6 === '[::1]' || v6 === '[0:0:0:0:0:0:0:1]') {
		return { ok: false, reason: 'loopback' };
	}
	// [::] is the IPv6 unspecified address ("any"), equivalent to 0.0.0.0.
	if (v6 === '[::]' || v6 === '[0:0:0:0:0:0:0:0]') {
		return { ok: false, reason: 'private_range' };
	}
	if (v6.startsWith('[fc') || v6.startsWith('[fd') || v6.startsWith('[fe80')) {
		return { ok: false, reason: 'private_range' };
	}

	// IPv4-mapped IPv6: [::ffff:a.b.c.d] — extract the embedded IPv4
	// and re-run the IPv4 private-range checks. The URL API may convert
	// dotted-quad to hex (e.g. 169.254 → a9fe), so we check both forms.
	const v4MappedDotted = v6.match(/^\[::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]$/);
	if (v4MappedDotted) {
		for (const pattern of PRIVATE_IPV4_PATTERNS) {
			if (pattern.test(v4MappedDotted[1])) {
				return { ok: false, reason: 'private_range' };
			}
		}
	}
	// Hex form: [::ffff:a9fe:a9fe] = [::ffff:169.254.169.254] (cloud metadata)
	// Block all IPv4-mapped IPv6 addresses as a conservative default — they
	// are almost never legitimate callback targets and are a known SSRF vector.
	if (v6.startsWith('[::ffff:')) {
		return { ok: false, reason: 'private_range' };
	}

	return { ok: true };
}
