import { VerificationSession } from './durable-objects/verification-session';
import { handleIndexRoutes } from './routes/index';
import { handleResultRoutes } from './routes/result';
import { handleTokenRoutes } from './routes/token';

export { VerificationSession };

// Per-isolate rate limiting (best-effort; for production use Cloudflare Rate
// Limiting rules at the edge). Each isolate keeps its own map, so this is a
// coarse throttle rather than a hard global limit.
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 30;

function checkRateLimit(ip: string): boolean {
	const now = Date.now();
	let entry = rateLimitMap.get(ip);
	if (!entry || now > entry.resetAt) {
		entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
		rateLimitMap.set(ip, entry);
	}
	entry.count++;
	// Periodic cleanup to bound the map size
	if (rateLimitMap.size > 10_000) {
		for (const [key, val] of rateLimitMap) {
			if (now > val.resetAt) rateLimitMap.delete(key);
		}
	}
	return entry.count <= RATE_LIMIT_MAX_REQUESTS;
}

// CORS allowlist. Add partner origins here — partners must be explicitly
// registered before their Origin is reflected in Access-Control-Allow-Origin.
// When the set is empty (or the request Origin is not listed), no CORS header
// is set at all, which means browsers will block cross-origin reads.
const ALLOWED_ORIGINS = new Set<string>([
	// Partner origins go here. Example:
	// 'https://partner1.example.com',
]);

/**
 * Return the CORS origin to allow for this request, or null if none.
 * null means: do not emit Access-Control-Allow-Origin (block cross-origin).
 */
function getAllowedOrigin(request: Request): string | null {
	const origin = request.headers.get('Origin');
	if (!origin) return null;
	if (ALLOWED_ORIGINS.has(origin)) return origin;
	return null;
}

export interface Env {
	// Durable Objects
	VERIFICATION_SESSION: DurableObjectNamespace<VerificationSession>;

	// Analytics Engine
	ANALYTICS: AnalyticsEngineDataset;

	// Static assets
	ASSETS: Fetcher;

	// Secrets (set via wrangler secret put or .dev.vars)
	ENCRYPTION_KEY: string;
	ENCRYPTION_ALGORITHM: string;

	// Vars (set in wrangler.jsonc [vars])
	ENABLE_FRONTEND_DEBUG: string;
}

export default {
	async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
		const { pathname } = url;

		// Set security headers on all responses (including early returns)
		const addSecurityHeaders = (response: Response): Response => {
			const newHeaders = new Headers(response.headers);
			newHeaders.set(
				'Permissions-Policy',
				'publickey-credentials-get=(self), publickey-credentials-create=(self), camera=(self)'
			);
			newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
			newHeaders.set('X-Content-Type-Options', 'nosniff');
			newHeaders.set('Referrer-Policy', 'no-referrer');
			newHeaders.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
			newHeaders.set(
				'Content-Security-Policy',
				"default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; frame-ancestors *;"
			);
			// CORS: reflect Origin only if it matches the partner allowlist.
			// When no origin is allowed, omit the header entirely (browsers
			// will block the cross-origin read rather than silently allow *).
			const allowedOrigin = getAllowedOrigin(request);
			if (allowedOrigin) {
				newHeaders.set('Access-Control-Allow-Origin', allowedOrigin);
			}
			// Advertise Vary: Origin whenever the request carries an Origin
			// header, even if this origin was not allowlisted. Otherwise a
			// shared cache could serve a no-ACAO response to an allowed
			// origin (or vice versa). When there is no Origin header at all,
			// the response does not vary on Origin, so we omit Vary.
			if (request.headers.get('Origin')) {
				newHeaders.set('Vary', 'Origin');
			}
			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: newHeaders,
			});
		};

		// Handle CORS preflight for API routes
		if (request.method === 'OPTIONS') {
			const allowedOrigin = getAllowedOrigin(request);
			const headers: Record<string, string> = {
				'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
				'Access-Control-Allow-Headers': 'Content-Type',
				'Access-Control-Max-Age': '86400',
			};
			if (allowedOrigin) {
				headers['Access-Control-Allow-Origin'] = allowedOrigin;
			}
			// See addSecurityHeaders: Vary: Origin must be advertised for any
			// request carrying an Origin header, regardless of allowlist match.
			if (request.headers.get('Origin')) {
				headers['Vary'] = 'Origin';
			}
			return addSecurityHeaders(new Response(null, { status: 204, headers }));
		}

		// Per-isolate rate limit on POST endpoints (30 requests / 60s per IP)
		if (request.method === 'POST') {
			const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
			if (!checkRateLimit(clientIp)) {
				return addSecurityHeaders(new Response(JSON.stringify({ error: 'rate_limited' }), {
					status: 429,
					headers: { 'Content-Type': 'application/json', 'Retry-After': '60' },
				}));
			}
		}

		try {
			let response: Response | null = null;

			// Token routes: /token, /token/iframeRender, /token/iframeCheck
			if (pathname.startsWith('/token')) {
				response = await handleTokenRoutes(request, env, url);
			}
			// Result routes: /result/success, /result/fail, /result/isSuccess
			else if (pathname.startsWith('/result')) {
				response = await handleResultRoutes(request, env, url);
			}
			// Index routes: /, /getVerificationPayloadAndUrl, /validateVerificationPayload, /callback, /test, /terms
			else if (
				pathname === '/' ||
				pathname === '/getVerificationPayloadAndUrl' ||
				pathname === '/validateVerificationPayload' ||
				pathname === '/callback' ||
				pathname === '/test' ||
				pathname === '/terms' ||
				pathname === '/terms/'
			) {
				response = await handleIndexRoutes(request, env, url);
			}

			if (response) {
				return addSecurityHeaders(response);
			}

			// Try static assets for everything else
			try {
				const assetResponse = await env.ASSETS.fetch(request);
				if (assetResponse.status !== 404) {
					return addSecurityHeaders(assetResponse);
				}
			} catch {
				// Asset fetch failed, fall through to 404
			}

			// 404 catch-all
			return addSecurityHeaders(new Response('404', { status: 404 }));
		} catch (err) {
			console.error('Unhandled error:', err);
			return addSecurityHeaders(new Response('Internal Server Error', { status: 500 }));
		}
	},
};
