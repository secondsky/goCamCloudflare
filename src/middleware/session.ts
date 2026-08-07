/**
 * Session middleware for Cloudflare Workers.
 * Uses an HMAC-signed cookie to track the session ID,
 * and routes requests to the correct DO instance.
 */
import type { Env } from '../index';
import type { VerificationSession } from '../durable-objects/verification-session';

const COOKIE_NAME = 'avs-session';
const SESSION_SEPARATOR = ':';
const hmacKeyCache = new Map<string, CryptoKey>();

export interface SessionContext {
	payloadHash: string;
	requestSessionId: string;
}

/**
 * Parse cookies from a request.
 */
export function parseCookies(request: Request): Record<string, string> {
	const cookieHeader = request.headers.get('Cookie') || '';
	const cookies: Record<string, string> = {};
	for (const pair of cookieHeader.split(';')) {
		const [name, ...rest] = pair.trim().split('=');
		if (name) {
			cookies[name] = rest.join('=');
		}
	}
	return cookies;
}

/**
 * Sign a session ID with HMAC-SHA256 for tamper protection.
 * Uses the HKDF-derived HMAC key (Uint8Array) for key separation from AES.
 */
async function signSessionId(sessionId: string, hmacKey: Uint8Array): Promise<string> {
	const encoder = new TextEncoder();
	const cacheKey = Array.from(hmacKey).join(',');
	let cryptoKey = hmacKeyCache.get(cacheKey);
	if (!cryptoKey) {
		cryptoKey = await crypto.subtle.importKey(
			'raw',
			hmacKey,
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign', 'verify']
		);
		hmacKeyCache.set(cacheKey, cryptoKey);
	}
	const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(sessionId));
	const sigHex = Array.from(new Uint8Array(signature))
		.map(b => b.toString(16).padStart(2, '0'))
		.join('');
	return `${sessionId}.${sigHex}`;
}

/**
 * Verify and extract session ID from a signed cookie value.
 * Uses crypto.subtle.verify for a constant-time MAC check.
 */
async function verifySessionId(signedValue: string, hmacKey: Uint8Array): Promise<string | null> {
	const dotIndex = signedValue.lastIndexOf('.');
	if (dotIndex === -1) return null;

	const sessionId = signedValue.substring(0, dotIndex);
	const signatureHex = signedValue.substring(dotIndex + 1);

	// Validate signature format (64 hex chars = 32-byte HMAC-SHA256)
	if (!/^[0-9a-f]{64}$/.test(signatureHex)) return null;

	const enc = new TextEncoder();
	const cacheKey = Array.from(hmacKey).join(',');
	let cryptoKey = hmacKeyCache.get(cacheKey);
	if (!cryptoKey) {
		cryptoKey = await crypto.subtle.importKey(
			'raw',
			hmacKey,
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign', 'verify']
		);
		hmacKeyCache.set(cacheKey, cryptoKey);
	}

	// Convert signatureHex back to bytes for verify
	const sigBytes = new Uint8Array(signatureHex.length / 2);
	for (let i = 0; i < signatureHex.length; i += 2) {
		sigBytes[i / 2] = parseInt(signatureHex.substring(i, i + 2), 16);
	}

	const valid = await crypto.subtle.verify(
		'HMAC',
		cryptoKey,
		sigBytes,
		enc.encode(sessionId)
	);

	return valid ? sessionId : null;
}

/**
 * Get the DO stub for the current session.
 * Uses a stable DO ID derived from the session name so all requests for the
 * same "verification flow" hit the same DO instance.
 *
 * The doName parameter is the session/verification identifier (e.g., a payload hash or session ID).
 */
export function getDoStub(env: Env, doName: string): DurableObjectStub<VerificationSession> {
	const id = env.VERIFICATION_SESSION.idFromName(doName);
	return env.VERIFICATION_SESSION.get(id);
}

/**
 * Decode a signed session value into payload hash + request session ID.
 */
function decodeSessionValue(value: string): SessionContext | null {
	const separatorIndex = value.indexOf(SESSION_SEPARATOR);
	if (separatorIndex === -1) return null;

	const payloadHash = value.substring(0, separatorIndex);
	const requestSessionId = value.substring(separatorIndex + 1);

	if (!payloadHash || !requestSessionId) return null;

	return { payloadHash, requestSessionId };
}

/**
 * Get session context from request cookies. Returns null if not found/invalid.
 */
export async function getSessionContextFromRequest(
	request: Request,
	hmacKey: Uint8Array
): Promise<SessionContext | null> {
	const cookies = parseCookies(request);
	const signedValue = cookies[COOKIE_NAME];
	if (!signedValue) return null;

	const verifiedValue = await verifySessionId(signedValue, hmacKey);
	if (!verifiedValue) return null;

	return decodeSessionValue(verifiedValue);
}

/**
 * Create a Set-Cookie header value for a new session.
 */
export async function createSessionCookie(
	payloadHash: string,
	requestSessionId: string,
	hmacKey: Uint8Array
): Promise<string> {
	const sessionValue = `${payloadHash}${SESSION_SEPARATOR}${requestSessionId}`;
	const signedValue = await signSessionId(sessionValue, hmacKey);
	return `${COOKIE_NAME}=${signedValue}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1200`;
}

/**
 * Helper to set a cookie on a Response.
 */
export function withCookie(response: Response, cookieValue: string): Response {
	const newHeaders = new Headers(response.headers);
	newHeaders.append('Set-Cookie', cookieValue);
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: newHeaders,
	});
}
