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

		// Handle CORS preflight for API routes
		if (request.method === 'OPTIONS') {
			return new Response(null, {
				status: 204,
				headers: {
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type',
					'Access-Control-Max-Age': '86400',
				},
			});
		}

		// Per-isolate rate limit on POST endpoints (30 requests / 60s per IP)
		if (request.method === 'POST') {
			const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
			if (!checkRateLimit(clientIp)) {
				return new Response(JSON.stringify({ error: 'rate_limited' }), {
					status: 429,
					headers: { 'Content-Type': 'application/json', 'Retry-After': '60' },
				});
			}
		}

		// Set security headers on all responses
		const addSecurityHeaders = (response: Response): Response => {
			const newHeaders = new Headers(response.headers);
			newHeaders.set(
				'Permissions-Policy',
				'publickey-credentials-get=(self), publickey-credentials-create=(self), camera=(self)'
			);
			newHeaders.set('Access-Control-Allow-Origin', '*');
			newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: newHeaders,
			});
		};

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
			// Index routes: /, /getVerificationPayloadAndUrl, /validateVerificationPayload, /callback, /test
			else if (
				pathname === '/' ||
				pathname === '/getVerificationPayloadAndUrl' ||
				pathname === '/validateVerificationPayload' ||
				pathname === '/callback' ||
				pathname === '/test'
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
					return assetResponse;
				}
			} catch {
				// Asset fetch failed, fall through to 404
			}

			// 404 catch-all
			return addSecurityHeaders(new Response('404', { status: 404 }));
		} catch (err) {
			console.error('Unhandled error:', err);
			return new Response('Internal Server Error', { status: 500 });
		}
	},
};
