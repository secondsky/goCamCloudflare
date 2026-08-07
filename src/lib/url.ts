/**
 * Validate that a callback URL is safe to fetch server-side.
 * Prevents SSRF by enforcing http(s) scheme and blocking private/loopback IPs.
 *
 * Note: this validates the hostname as written. For hostnames that resolve
 * dynamically, a DNS-rebinding attack is still theoretically possible.
 * A production deployment should pair this with a partner-host allowlist.
 */

const PRIVATE_IPV4_PATTERNS: RegExp[] = [
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

	// IPv6 loopback / link-local / unique-local
	if (hostname === '[::1]' || hostname === '[0:0:0:0:0:0:0:1]') {
		return { ok: false, reason: 'loopback' };
	}
	if (hostname.startsWith('[fc') || hostname.startsWith('[fd') || hostname.startsWith('[fe80')) {
		return { ok: false, reason: 'private_range' };
	}

	return { ok: true };
}
