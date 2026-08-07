/**
 * Result routes — replaces source/backend/app/route/result.ts
 * Handles: POST /result/success, POST /result/fail, POST /result/isSuccess
 */
import type { Env } from '../index';
import { getConfig } from '../config';
import { AvsResponse } from '../lib/response';
import { constantTimeEqual } from '../lib/crypto-utils';
import { callDoJson } from '../lib/do';
import { safeParseInt } from '../lib/parse';
import { getDoStub, getSessionContextFromRequest } from '../middleware/session';
import {
	isValidStep,
	SESSION_STATE_SUCCESS,
	SESSION_STATE_FAILED,
} from '../durable-objects/verification-session';

const MAX_TEST_DURATION = 20 * 60 * 1000; // 20 minutes

/**
 * Check that a client-supplied token matches the server-stored key.
 * Exported for unit testing. Uses constant-time comparison to avoid
 * timing side-channels on the successKey/failKey check.
 */
export function tokenIsValid(token: unknown, storedKey: string | undefined): boolean {
	if (typeof storedKey !== 'string' || typeof token !== 'string') return false;
	return constantTimeEqual(token, storedKey);
}

interface RequestSessionData {
	successKey?: string;
	failKey?: string;
	accessTime?: number;
	sessionStartId: string;
	payloadHash?: string;
	payload?: string;
}

export async function handleResultRoutes(request: Request, env: Env, url: URL): Promise<Response | null> {
	const { pathname } = url;
	const method = request.method;
	const config = await getConfig(env);

	if (method !== 'POST') return null;

	// Parse body — reject malformed requests with 400
	let body: any;
	try {
		const contentType = request.headers.get('Content-Type') || '';
		if (contentType.includes('application/json')) {
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

	// Get payloadHash + request session id from signed cookie.
	const sessionContext = await getSessionContextFromRequest(request, config.encryption.hmacKey);

	// POST /result/success
	if (pathname === '/result/success') {
		const token                      = body.token;
		const stepId                     = safeParseInt(body.stepId, 0);
		const idCountry                  = body.idCountry || '';
		const idState                    = body.idState || '';
		const idType                     = body.idType || '';

		const sessionResult = {
			stepId,
			idCountry,
			idState,
			idType,
			errorCode: 0,
		};

		if (!isValidStep(stepId)) {
			sessionResult.stepId    = 0;
			sessionResult.errorCode = 30007;
			return Response.json(AvsResponse.errorResponse(30007, 'Invalid step id'));
		}

		if (!sessionContext) {
			return Response.json(AvsResponse.errorResponse(30010, 'Session not found'));
		}

		const stub = getDoStub(env, sessionContext.payloadHash);

		// Get request session data from DO
		let reqSession: RequestSessionData | null = null;
		try {
			reqSession = await callDoJson<RequestSessionData | null>(stub, 'getRequestSession', {
				sessionId: sessionContext.requestSessionId,
			});
		} catch (err) {
			console.error('DO getRequestSession error:', err);
			reqSession = null;
		}

		if (!reqSession) {
			return Response.json(AvsResponse.errorResponse(30010, 'Session not found'));
		}

		// Check max test duration
		if (reqSession.accessTime && (Date.now() - reqSession.accessTime) >= MAX_TEST_DURATION) {
			sessionResult.errorCode = 30008;
			try {
				await callDoJson<{ success: boolean }>(stub, 'updateState', {
					sessionId: reqSession.sessionStartId,
					stateData: sessionResult,
				});
			} catch (err) {
				console.error('DO updateState error:', err);
			}
			return Response.json(AvsResponse.errorResponse(30008, 'Test max allowed time expired'));
		}

		// Verify token (always required — no bypass via deviceLocationVerification)
		if (!tokenIsValid(token, reqSession.successKey)) {
			sessionResult.errorCode = 30009;
			try {
				await callDoJson<{ success: boolean }>(stub, 'updateState', {
					sessionId: reqSession.sessionStartId,
					stateData: sessionResult,
				});
			} catch (err) {
				console.error('DO updateState error:', err);
			}
			return Response.json(AvsResponse.errorResponse(30009, 'Invalid token'));
		}

		// End session as success
		let endResult: any;
		try {
			endResult = await callDoJson<any>(stub, 'end', {
				sessionId:       reqSession.sessionStartId,
				sessionStateInt: SESSION_STATE_SUCCESS,
				stepIp:          stepId,
				errorCode:       0,
				idCountry,
				idState,
				idType,
			});
		} catch (err) {
			console.error('DO end error:', err);
			return Response.json(AvsResponse.errorResponse(30010, 'Failed to save session data'));
		}

		if (!endResult || !endResult.payload) {
			sessionResult.errorCode = 30010;
			return Response.json(AvsResponse.errorResponse(30010, 'Failed to save session data'));
		}

		const successPayload = endResult.payload;

		// Set the isAgeVerified cookie
		const cookieValue = `isAgeVerified=${successPayload}; Path=/; Max-Age=${config.cookie.maxAge / 1000}${config.cookie.secure ? '; Secure' : ''}${config.cookie.httpOnly ? '; HttpOnly' : ''}; SameSite=${config.cookie.sameSite}`;

		const response = Response.json(AvsResponse.successResponse({
			successPayload,
		}));

		const newHeaders = new Headers(response.headers);
		newHeaders.append('Set-Cookie', cookieValue);
		return new Response(response.body, {
			status: response.status,
			headers: newHeaders,
		});
	}

	// POST /result/fail
	if (pathname === '/result/fail') {
		const token                      = body.token;
		const stepId                     = safeParseInt(body.stepId, 0);
		const errorCode                  = safeParseInt(body.errorCode, 0);
		const idCountry                  = body.idCountry || '';
		const idState                    = body.idState || '';
		const idType                     = body.idType || '';

		const sessionResult = {
			stepId,
			idCountry,
			idState,
			idType,
			errorCode,
		};

		if (!isValidStep(stepId)) {
			sessionResult.stepId    = 0;
			sessionResult.errorCode = 30011;
			return Response.json(AvsResponse.errorResponse(30011, 'Invalid step id'));
		}

		if (!sessionContext) {
			return Response.json(AvsResponse.errorResponse(30014, 'Session not found'));
		}

		const stub = getDoStub(env, sessionContext.payloadHash);

		// Get request session data from DO
		let reqSession: RequestSessionData | null = null;
		try {
			reqSession = await callDoJson<RequestSessionData | null>(stub, 'getRequestSession', {
				sessionId: sessionContext.requestSessionId,
			});
		} catch (err) {
			console.error('DO getRequestSession error:', err);
			reqSession = null;
		}

		if (!reqSession) {
			return Response.json(AvsResponse.errorResponse(30014, 'Session not found'));
		}

		// Check max test duration
		if (reqSession.accessTime && (Date.now() - reqSession.accessTime) >= MAX_TEST_DURATION) {
			sessionResult.errorCode = 30012;
			try {
				await callDoJson<{ success: boolean }>(stub, 'updateState', {
					sessionId: reqSession.sessionStartId,
					stateData: sessionResult,
				});
			} catch (err) {
				console.error('DO updateState error:', err);
			}
			return Response.json(AvsResponse.errorResponse(30012, 'Test max allowed time expired'));
		}

		// Verify token (always required — no bypass via deviceLocationVerification)
		if (!tokenIsValid(token, reqSession.failKey)) {
			sessionResult.errorCode = 30013;
			try {
				await callDoJson<{ success: boolean }>(stub, 'updateState', {
					sessionId: reqSession.sessionStartId,
					stateData: sessionResult,
				});
			} catch (err) {
				console.error('DO updateState error:', err);
			}
			return Response.json(AvsResponse.errorResponse(30013, 'Invalid token'));
		}

		// End session as fail
		let endResult: any;
		try {
			endResult = await callDoJson<any>(stub, 'end', {
				sessionId:       reqSession.sessionStartId,
				sessionStateInt: SESSION_STATE_FAILED,
				stepIp:          stepId,
				errorCode,
				idCountry,
				idState,
				idType,
			});
		} catch (err) {
			console.error('DO end error:', err);
			return Response.json(AvsResponse.errorResponse(30014, 'Failed to save session data'));
		}

		if (!endResult || typeof endResult.payload !== 'string') {
			sessionResult.errorCode = 30014;
			return Response.json(AvsResponse.errorResponse(30014, 'Failed to save session data'));
		}

		return Response.json(AvsResponse.successResponse());
	}

	// POST /result/isSuccess
	if (pathname === '/result/isSuccess') {
		// Require the signed avs-session cookie. Previously this endpoint was
		// pollable without a cookie and used an attacker-supplied payload prefix.
		if (!sessionContext) {
			return Response.json(AvsResponse.errorResponse(30010, 'Session not found'));
		}

		const stub = getDoStub(env, sessionContext.payloadHash);
		let checkResult: any;
		try {
			checkResult = await callDoJson<{ isValidated: boolean }>(stub, 'isPayloadValidated', {
				payloadHash: sessionContext.payloadHash,
			});
		} catch (err) {
			console.error('DO isPayloadValidated error:', err);
			return Response.json(AvsResponse.errorResponse(30010, 'Session lookup failed'));
		}

		return Response.json(AvsResponse.successResponse({
			isValidated: checkResult?.isValidated || false,
		}));
	}

	return null;
}
