/**
 * Token routes — replaces source/backend/app/route/token.ts
 * Handles: GET /token, GET /token/iframeRender, GET /token/iframeCheck
 */
import type { Env } from '../index';
import { getConfig, type AppConfig } from '../config';
import { AvsEncryption } from '../lib/encryption';
import { AvsRandom } from '../lib/random';
import { callDoJson } from '../lib/do';
import { sanitizeColorConfig } from '../lib/color';
import { getDoStub, createSessionCookie, withCookie, parseCookies } from '../middleware/session';
import { renderTokenIndex } from '../templates/token-index';
import { renderTokenEmbedCheck } from '../templates/token-embed-check';
import { renderTokenError } from '../templates/token-error';
import { VERIFICATION_STANDARD_V1, VERIFICATION_IFRAME_V1, SESSION_STATE_IN_PROGRESS } from '../durable-objects/verification-session';
import UAParser from 'ua-parser-js';

interface DoStartResponse {
	sessionId: string;
	linkBack: string;
}

export async function handleTokenRoutes(request: Request, env: Env, url: URL): Promise<Response | null> {
	const { pathname } = url;
	const method = request.method;
	const config = await getConfig(env);

	if (method !== 'GET') return null;

	// GET /token/iframeCheck
	if (pathname === '/token/iframeCheck') {
		const cookies = parseCookies(request);
		const isAgeVerified = typeof cookies['isAgeVerified'] !== 'undefined' && cookies['isAgeVerified'] !== '';
		const verificationPayload = isAgeVerified ? cookies['isAgeVerified'] : null;

		const html = renderTokenEmbedCheck({
			js: {
				isAgeVerified,
				verificationPayload,
			},
			cacheBuster: config.cacheBuster,
		});

		return new Response(html, {
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}

	// GET /token/iframeRender
	if (pathname === '/token/iframeRender') {
		return renderTokenPage(request, env, url, config, VERIFICATION_IFRAME_V1);
	}

	// GET /token
	if (pathname === '/token') {
		return renderTokenPage(request, env, url, config, VERIFICATION_STANDARD_V1);
	}

	return null;
}

async function renderTokenPage(
	request: Request,
	env: Env,
	url: URL,
	config: AppConfig,
	verificationVersion: number
): Promise<Response> {
	const payload = url.searchParams.get('d');

	if (!payload) {
		const html = renderTokenError(30005, 'Invalid payload');
		return new Response(html, {
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}

	// Use a DO instance keyed by the payload hash
	const payloadHash = await AvsEncryption.computePayloadHash(payload);
	const stub = getDoStub(env, payloadHash);

	let avsSession: DoStartResponse | null = null;
	try {
		const startResult = await callDoJson<any>(stub, 'start', {
				payload,
		});
		// Only render the verification page for sessions that are still
		// IN_PROGRESS. Expired or already-used links (LINK_EXPIRED,
		// LINK_ALREADY_USED) must not produce a verifiable session.
		if (startResult && typeof startResult.sessionId === 'string' && startResult.sessionState === SESSION_STATE_IN_PROGRESS) {
			avsSession = {
				sessionId: startResult.sessionId,
				linkBack: typeof startResult.linkBack === 'string' ? startResult.linkBack : '/',
			};
		}
	} catch (e) {
		console.log('DO start error:', e);
	}

	if (!avsSession) {
		const html = renderTokenError(30006, 'Invalid payload');
		return new Response(html, {
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}

	// Decrypt payload for template data
	let payloadParsed: any;
	try {
		payloadParsed = await AvsEncryption.decryptString(payload, config.encryption.aesKey);
	} catch {
		const html = renderTokenError(30006, 'Invalid payload');
		return new Response(html, {
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}

	const successKey = AvsRandom.generateRandomString(32);
	const failKey    = AvsRandom.generateRandomString(32);
	const sessionId  = avsSession.sessionId;
	const ipCountry  = payloadParsed.userIpCountry || 'FR';
	const requestSessionId = crypto.randomUUID();

	// Store request session data in DO (successKey, failKey, accessTime)
	try {
		await callDoJson<{ success: boolean }>(stub, 'storeRequestSession', {
			sessionId: requestSessionId,
			data: {
				successKey,
				failKey,
				accessTime:     Date.now(),
				sessionStartId: sessionId,
				payloadHash:    payloadHash,
				payload,
			},
		});
	} catch (e) {
		console.log('DO storeRequestSession error:', e);
		const html = renderTokenError(30006, 'Invalid payload');
		return new Response(html, {
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		});
	}

	let userAgent: any = '';
	const uaString = request.headers.get('User-Agent') || '';
	try {
		userAgent = UAParser(uaString);
	} catch {
		userAgent = uaString;
	}

	const html = renderTokenIndex({
		js: {
			onDocumentReady:       'AvsToken.main',
			token:                 AvsEncryption.base64EncodeObject({
				successKey,
				failKey,
				backLink: avsSession.linkBack,
			}),
			isLiveness:            true,
			showDetectedAgeNumber: payloadParsed.httpParamList?.showDetectedAgeNumber || false,
			verificationTypeList:  payloadParsed.httpParamList?.verificationTypeList || [],
			verificationVersion:   verificationVersion,
			d:                     payload,
			sessionId:             sessionId,
			partnerColorConfig:    sanitizeColorConfig(payloadParsed.userData?.colorConfig),
			ipCountry:             ipCountry,
			deviceInfo:            userAgent,
			countryAgeMajority:    config.countryAgeMajority,
		},
		debug: config.enableFrontEndDebug,
		cacheBuster: config.cacheBuster,
	});

	// Set session cookie so result routes can find this session
	const cookie = await createSessionCookie(payloadHash, requestSessionId, config.encryption.hmacKey);

	return withCookie(
		new Response(html, {
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		}),
		cookie
	);
}
