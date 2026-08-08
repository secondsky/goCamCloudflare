/**
 * Index routes — replaces source/backend/app/route/index.ts
 * Handles: GET /, POST /getVerificationPayloadAndUrl,
 *          POST /validateVerificationPayload, POST /callback, GET /test
 */
import type { Env } from '../index';
import { getConfig } from '../config';
import { AvsEncryption } from '../lib/encryption';
import { isSafeCallbackUrl } from '../lib/url';
import { AvsResponse } from '../lib/response';
import { renderHome } from '../templates/home';
import { VERIFICATION_IFRAME_V1, SESSION_STATE_SUCCESS } from '../durable-objects/verification-session';

export async function handleIndexRoutes(request: Request, env: Env, url: URL): Promise<Response | null> {
	const { pathname } = url;
	const method = request.method;
	const config = await getConfig(env);

	// GET /
	if (pathname === '/' && method === 'GET') {
		const html = renderHome({
			js: {
				onDocumentReady: 'AvsHome.main',
			},
			cacheBuster: config.cacheBuster,
			nodeEnv: 'production',
		});
		return new Response(html, {
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}

	// GET /test
	if (pathname === '/test' && method === 'GET') {
		return new Response('test');
	}

	// POST /getVerificationPayloadAndUrl
	if (pathname === '/getVerificationPayloadAndUrl' && method === 'POST') {
		const formData = await request.formData();

		const colorConfigBodyBackgroundInput      = formData.get('colorConfigBodyBackgroundInput');
		const colorConfigBodyForegroundInput      = formData.get('colorConfigBodyForegroundInput');
		const colorConfigButtonBackgroundInput    = formData.get('colorConfigButtonBackgroundInput');
		const colorConfigButtonForegroundInput    = formData.get('colorConfigButtonForegroundInput');
		const colorConfigButtonForegroundCTAInput = formData.get('colorConfigButtonForegroundCTAInput');
		const callbackUrl                         = formData.get('callbackUrl');
		const demoPageUrl                         = formData.get('demoPageUrl');

		if (
			colorConfigBodyBackgroundInput == undefined ||
			colorConfigBodyForegroundInput == undefined ||
			colorConfigButtonBackgroundInput == undefined ||
			colorConfigButtonForegroundInput == undefined ||
			colorConfigButtonForegroundCTAInput == undefined ||
			callbackUrl == undefined
		) {
			return Response.json(AvsResponse.errorResponse(30000, 'Invalid payload config'));
		}

		if (typeof callbackUrl !== 'string' || callbackUrl.trim() === '') {
			return Response.json(AvsResponse.errorResponse(30000, 'Invalid payload config'));
		}
		const urlCheck = isSafeCallbackUrl(callbackUrl);
		if (!urlCheck.ok) {
			return Response.json(AvsResponse.errorResponse(30000, `Invalid callback URL: ${urlCheck.reason}`));
		}

		let demoPageUrlInstance: URL;
		try {
			const demoPageUrlString = typeof demoPageUrl === 'string' && demoPageUrl.trim() !== ''
				? demoPageUrl
				: url.origin;
			demoPageUrlInstance = new URL(demoPageUrlString);
		} catch {
			return Response.json(AvsResponse.errorResponse(30000, 'Invalid demo page URL'));
		}

		const userAgent         = request.headers.get('User-Agent') || '';
		const linkBack          = '/';
		const requestCf = request.cf as { country?: string; regionCode?: string } | undefined;
		const userIpCountry     = requestCf?.country;
		const userIpState       = requestCf?.regionCode;
		const userIp            = request.headers.get('CF-Connecting-IP');

		// Fail closed: this service must run behind the Cloudflare edge, which
		// populates request.cf.country/regionCode and the CF-Connecting-IP header.
		// If any are missing, reject rather than silently defaulting to US/TX.
		if (!userIpCountry || !userIpState || !userIp) {
			return Response.json(
				AvsResponse.errorResponse(30000, 'Unable to determine client location. This service must be accessed via the Cloudflare edge.')
			);
		}

		const creationTimestamp = Date.now();
		const testPathRedirect  = '/token';
		const testPathIframe    = '/token/iframeCheck';
		const websiteHostname   = url.hostname;

		const requestPayload = await AvsEncryption.encryptObject(
			{
				userData: {
					userId: 0,
					colorConfig: {
						body: {
							background: colorConfigBodyBackgroundInput,
							foreground: colorConfigBodyForegroundInput,
							button: {
								background:             colorConfigButtonBackgroundInput,
								foreground:             colorConfigButtonForegroundInput,
								foregroundCallToAction:  colorConfigButtonForegroundCTAInput,
							},
						},
					},
				},
				httpUserAgent:       userAgent,
				websiteHostname:     websiteHostname,
				httpParamList: {
					userAgent:              userAgent,
					websiteHostname:        websiteHostname,
					showDetectedAgeNumber:  true,
					verificationTypeList:   ['selfie', 'scanId'],
				},
				verificationVersion: VERIFICATION_IFRAME_V1,
				linkBack:            linkBack,
				userIpCountry:       userIpCountry,
				userIpState:         userIpState,
				userIpStr:           userIp,
				callbackUrl:         callbackUrl,
				creationTimestamp:    creationTimestamp,
			},
			config.encryption.aesKey
		);

		// Build URLs
		const tokenUrl = new URL(testPathRedirect, demoPageUrlInstance.origin);
		tokenUrl.searchParams.set('d', requestPayload);

		const iframeUrl = new URL(testPathIframe, demoPageUrlInstance.origin);
		iframeUrl.searchParams.set('d', requestPayload);

		return Response.json(AvsResponse.successResponse({
			payload:   requestPayload,
			url:       tokenUrl.toString(),
			iframeUrl: iframeUrl.toString(),
		}));
	}

	// POST /validateVerificationPayload
	if (pathname === '/validateVerificationPayload' && method === 'POST') {
		let body: any;
		try {
			const ct = request.headers.get('Content-Type') || '';
			if (ct.includes('application/json')) {
				body = await request.json();
			} else {
				const formData = await request.formData();
				body = Object.fromEntries(formData);
			}
			if (!body || typeof body !== 'object') {
				return Response.json(AvsResponse.errorResponse(30000, 'Invalid request body'), { status: 400 });
			}
		} catch {
			return Response.json(AvsResponse.errorResponse(30000, 'Malformed request body'), { status: 400 });
		}

		const verificationPayload = body.verificationPayload;

		if (typeof verificationPayload === 'undefined') {
			return Response.json(AvsResponse.errorResponse(30001, 'Invalid payload'));
		}

		let payloadParsed: any;
		try {
			payloadParsed = await AvsEncryption.decryptString(verificationPayload, config.encryption.aesKey);
		} catch {
			return Response.json(AvsResponse.errorResponse(30002, 'Verification payload integrity check failed'));
		}

		if (typeof payloadParsed.verificationResult === 'undefined') {
			return Response.json(AvsResponse.errorResponse(30002, 'Verification payload integrity check failed'));
		}

		if (payloadParsed.verificationResult.stateInt !== SESSION_STATE_SUCCESS) {
			return Response.json(AvsResponse.errorResponse(30003, 'Payload state invalid'));
		}

		return Response.json(AvsResponse.successResponse({
			sessionId: payloadParsed.verificationResult.sessionId,
		}));
	}

	// POST /callback
	if (pathname === '/callback' && method === 'POST') {
		let body: any;
		try {
			const ct = request.headers.get('Content-Type') || '';
			if (ct.includes('application/json')) {
				body = await request.json();
			} else {
				const formData = await request.formData();
				body = Object.fromEntries(formData);
			}
			if (!body || typeof body !== 'object') {
				return Response.json(AvsResponse.errorResponse(30000, 'Invalid request body'), { status: 400 });
			}
		} catch {
			return Response.json(AvsResponse.errorResponse(30000, 'Malformed request body'), { status: 400 });
		}

		// Log only non-identifying metadata. Never log the raw body
		// (it contains user IP, userData, device info — PII).
		const callbackState = typeof body.stateInt !== 'undefined' ? String(body.stateInt) : 'unknown';
		const sessionId = typeof body.sessionId === 'string' ? body.sessionId : '';

		console.log('Callback received', { stateInt: callbackState, sessionId });

		// Write only non-identifying fields to Analytics Engine
		try {
			env.ANALYTICS.writeDataPoint({
				blobs: ['callback_received', callbackState, sessionId],
				doubles: [Date.now()],
				indexes: ['callback'],
			});
		} catch {
			// Analytics Engine may not be available in dev
		}

		return Response.json(AvsResponse.successResponse());
	}

	return null;
}
