import { DurableObject } from 'cloudflare:workers';
import { AvsEncryption } from '../lib/encryption';
import { hkdfDerive } from '../lib/crypto-utils';
import type { Env } from '../index';

// ─── Constants ───

export const VERIFICATION_STANDARD_V1 = 1;
export const VERIFICATION_IFRAME_V1   = 2;

export const SESSION_STATE_IN_PROGRESS       = 1;
export const SESSION_STATE_SUCCESS           = 2;
export const SESSION_STATE_FAILED            = 3;
export const SESSION_STATE_LINK_EXPIRED      = 4;
export const SESSION_STATE_LINK_ALREADY_USED = 5;

export const STEP_START_PAGE                         = 1;
export const STEP_SELFIE_AGE_DETECTION_INTRO         = 2;
export const STEP_SELFIE_AGE_DETECTION_PAGE          = 3;
export const STEP_SCAN_ID_AGE_VERIFICATION_INTRO     = 4;
export const STEP_SCAN_ID_AGE_VERIFICATION_PAGE      = 5;
export const STEP_CREDIT_CARD_AGE_VERIFICATION_INTRO = 6;
export const STEP_CREDIT_CARD_AGE_VERIFICATION_PAGE  = 7;

const VALID_STEPS = [
	STEP_START_PAGE,
	STEP_SELFIE_AGE_DETECTION_INTRO,
	STEP_SELFIE_AGE_DETECTION_PAGE,
	STEP_SCAN_ID_AGE_VERIFICATION_INTRO,
	STEP_SCAN_ID_AGE_VERIFICATION_PAGE,
	STEP_CREDIT_CARD_AGE_VERIFICATION_INTRO,
	STEP_CREDIT_CARD_AGE_VERIFICATION_PAGE,
];

const STATE_MAP: Record<number, string> = {
	[SESSION_STATE_IN_PROGRESS]:       'inProgress',
	[SESSION_STATE_SUCCESS]:           'success',
	[SESSION_STATE_FAILED]:            'fail',
	[SESSION_STATE_LINK_EXPIRED]:      'expired',
	[SESSION_STATE_LINK_ALREADY_USED]: 'alreadyUsed',
};

const PAYLOAD_EXPIRATION_TIME = 10 * 60 * 1000;
const CALLBACK_TIMEOUT_MS = 5000;
const REQUEST_SESSION_RETENTION_TIME = 2 * 60 * 60 * 1000;

// ─── Interfaces ───

export interface SessionData {
	sessionId: string;
	userData: any;
	ip: string;
	ipCountry: string;
	ipState: string;
	websiteHostname: string;
	verificationVersion: number;
	deviceType?: string;
	userAgent: string;
	state: string;
	stateInt: number;
	callbackUrl: string;
	payload: string;
	stepIp?: number;
	idCountry?: string;
	idState?: string;
	idType?: string;
	errorCode?: number;
	linkBack?: string;
}

export interface StartResult {
	sessionInfo: SessionData | null;
	sessionId: string;
	sessionState: number;
	linkBack: string;
	http: {
		userAgent: string;
		paramList: any;
	};
}

export interface StateData {
	stepId: number;
	idCountry: string;
	idState: string;
	idType: string;
	errorCode: number;
}

// ─── Helpers ───

export function isValidStep(step: number): boolean {
	return VALID_STEPS.includes(step);
}

export function getStateMap(): Record<number, string> {
	return STATE_MAP;
}

// ─── Durable Object ───

export class VerificationSession extends DurableObject<Env> {
	private initialized = false;
	private _aesKeyPromise: Promise<Uint8Array> | null = null;

	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
	}

	/**
	 * Derive (and cache) the HKDF AES subkey for this DO instance.
	 * The DO reads ENCRYPTION_KEY directly from env (it does not go through
	 * getConfig), so it derives its own AES key with the same context string
	 * ('avs/aes/v1') used by getConfig. Cached so the HKDF runs once per DO.
	 */
	private async getAesKey(): Promise<Uint8Array> {
		if (!this._aesKeyPromise) {
			this._aesKeyPromise = hkdfDerive(this.env.ENCRYPTION_KEY, 'avs/aes/v1', 32);
		}
		return this._aesKeyPromise;
	}

	private ensureInitialized(): void {
		if (this.initialized) return;
		this.ctx.storage.sql.exec(`
			CREATE TABLE IF NOT EXISTS sessions (
				sessionId TEXT PRIMARY KEY,
				payloadHash TEXT,
				stateInt INTEGER DEFAULT 1,
				data TEXT NOT NULL,
				createdAt INTEGER NOT NULL
			);
			CREATE TABLE IF NOT EXISTS payloads (
				payloadHash TEXT PRIMARY KEY,
				payload TEXT NOT NULL,
				creationTimestamp INTEGER NOT NULL,
				createdAt INTEGER NOT NULL
			);
			CREATE TABLE IF NOT EXISTS audit_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				sessionId TEXT,
				event TEXT NOT NULL,
				detail TEXT,
				timestamp INTEGER NOT NULL
			);
				CREATE TABLE IF NOT EXISTS request_sessions (
					sessionId TEXT PRIMARY KEY,
					data TEXT NOT NULL,
					createdAt INTEGER NOT NULL
				);
				CREATE INDEX IF NOT EXISTS idx_sessions_payload_state
					ON sessions (payloadHash, stateInt);
				CREATE INDEX IF NOT EXISTS idx_request_sessions_createdAt
					ON request_sessions (createdAt);
			`);
			this.initialized = true;
		}

	/**
	 * Handle incoming requests to the DO.
	 * Routes internally based on the URL path.
	 */
	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const action = url.pathname.split('/').pop();

		try {
			switch (action) {
				case 'start': {
					const body = await request.json() as { payload: string };
					const result = await this.startSession(body.payload);
					return Response.json(result);
				}
				case 'end': {
					const body = await request.json() as {
						sessionId: string;
						sessionStateInt: number;
						stepIp: number;
						errorCode: number;
						idCountry: string;
						idState: string;
						idType: string;
					};
					const result = await this.endSession(
						body.sessionId, body.sessionStateInt, body.stepIp,
						body.errorCode, body.idCountry, body.idState, body.idType
					);
					return Response.json(result);
				}
				case 'updateState': {
					const body = await request.json() as { sessionId: string; stateData: StateData };
					const result = this.updateState(body.sessionId, body.stateData);
					return Response.json({ success: result });
				}
				case 'isPayloadValidated': {
					const body = await request.json() as { payloadHash: string };
					const result = this.isPayloadValidated(body.payloadHash);
					return Response.json({ isValidated: result });
				}
				case 'getSession': {
					const body = await request.json() as { sessionId: string };
					const result = this.getById(body.sessionId);
					return Response.json(result);
				}
				case 'storeRequestSession': {
					const body = await request.json() as { sessionId: string; data: Record<string, any> };
					this.storeRequestSession(body.sessionId, body.data);
					return Response.json({ success: true });
				}
				case 'getRequestSession': {
					const body = await request.json() as { sessionId: string };
					const result = this.getRequestSession(body.sessionId);
					return Response.json(result);
				}
				default:
					return new Response('Unknown action', { status: 400 });
			}
		} catch (err) {
			console.error('DO error:', err);
			return Response.json({ error: 'internal_error' }, { status: 500 });
		}
	}

	// ─── Session Methods ───

	private async startSession(payload: string): Promise<StartResult | null> {
		this.ensureInitialized();

		const aesKey = await this.getAesKey();
		const payloadParsed = await AvsEncryption.decryptString(payload, aesKey);
		const sessionId = crypto.randomUUID();
		const payloadHash = payload.substring(0, 64);

		// Check payload state
		let sessionState = SESSION_STATE_IN_PROGRESS;
		if (this.isPayloadStored(payloadHash)) {
			sessionState = SESSION_STATE_LINK_ALREADY_USED;
		}
		// Fix #13: Check expiry against the creationTimestamp from the decrypted payload
		if (payloadParsed.creationTimestamp &&
			(payloadParsed.creationTimestamp + PAYLOAD_EXPIRATION_TIME) < Date.now()) {
			sessionState = SESSION_STATE_LINK_EXPIRED;
		}

		// Store payload
		this.storePayload(payloadHash, payload, payloadParsed.creationTimestamp || Date.now());

		const sessionData: SessionData = {
			sessionId,
			userData:            payloadParsed.userData,
			ip:                  payloadParsed.userIpStr,
			ipCountry:           payloadParsed.userIpCountry,
			ipState:             payloadParsed.userIpState,
			websiteHostname:     payloadParsed.websiteHostname,
			verificationVersion: payloadParsed.verificationVersion,
			deviceType:          undefined,
			userAgent:           payloadParsed.httpParamList?.userAgent || '',
			stateInt:            sessionState,
			state:               STATE_MAP[sessionState],
			callbackUrl:         payloadParsed.callbackUrl,
			payload,
			linkBack:            payloadParsed.linkBack,
		};

		// Store in SQLite with payloadHash for indexed lookup
		this.ctx.storage.sql.exec(
			`INSERT OR REPLACE INTO sessions (sessionId, payloadHash, stateInt, data, createdAt) VALUES (?, ?, ?, ?, ?)`,
			sessionId,
			payloadHash,
			sessionState,
			JSON.stringify(sessionData),
			Date.now()
		);

		// Audit log
		this.ctx.storage.sql.exec(
			`INSERT INTO audit_log (sessionId, event, detail, timestamp) VALUES (?, ?, ?, ?)`,
			sessionId, 'session_created', JSON.stringify({ state: STATE_MAP[sessionState] }), Date.now()
		);

		return {
			sessionInfo:  sessionData,
			sessionId,
			sessionState,
			linkBack:     payloadParsed.linkBack,
			http: {
				userAgent: payloadParsed.httpParamList?.userAgent || '',
				paramList: payloadParsed.httpParamList,
			},
		};
	}

	private async endSession(
		sessionId: string,
		sessionStateInt: number,
		stepIp: number,
		errorCode: number,
		idCountry: string,
		idState: string,
		idType: string
	): Promise<{ payload: string } | null> {
		this.ensureInitialized();

		const aesKey = await this.getAesKey();
		const sessionData = this.getById(sessionId);
		if (!sessionData) return null;

		sessionData.stateInt  = sessionStateInt;
		sessionData.state     = STATE_MAP[sessionStateInt];
		sessionData.stepIp    = stepIp;
		sessionData.idCountry = idCountry;
		sessionData.idState   = idState;
		sessionData.idType    = idType;
		sessionData.errorCode = errorCode;

		// Dispatch callback in background so user-facing completion is not blocked.
		if (sessionData.callbackUrl) {
			this.ctx.waitUntil(
				this.dispatchCallback(sessionData, sessionStateInt, sessionId, errorCode, stepIp, idCountry, idState, idType)
			);
		}

		// Update session in SQLite
		this.ctx.storage.sql.exec(
			`INSERT OR REPLACE INTO sessions (sessionId, payloadHash, stateInt, data, createdAt) VALUES (?, ?, ?, ?, ?)`,
			sessionId,
			sessionData.payload ? sessionData.payload.substring(0, 64) : null,
			sessionStateInt,
			JSON.stringify(sessionData),
			Date.now()
		);

		// Audit log
		this.ctx.storage.sql.exec(
			`INSERT INTO audit_log (sessionId, event, detail, timestamp) VALUES (?, ?, ?, ?)`,
			sessionId,
			'session_ended',
			JSON.stringify({ state: STATE_MAP[sessionStateInt], errorCode }),
			Date.now()
		);

		// Build result payload (same format as original)
		const decryptedPayload = await AvsEncryption.decryptString(sessionData.payload, aesKey);
		decryptedPayload.userIpStr          = '127.0.0.1';
		decryptedPayload.userIpCountry      = 'A1';
		decryptedPayload.userData           = sessionData.userData;
		decryptedPayload.callbackUrl        = '';
		decryptedPayload.verificationResult = {
			state:     STATE_MAP[sessionStateInt],
			stateInt:  sessionStateInt,
			sessionId,
			errorCode,
		};

		return {
			payload: await AvsEncryption.encryptObject(decryptedPayload, aesKey),
		};
	}

	private updateState(sessionId: string, stateData: StateData): boolean {
		this.ensureInitialized();

		const sessionData = this.getById(sessionId);
		if (!sessionData) return false;

		sessionData.stepIp    = stateData.stepId;
		sessionData.idCountry = stateData.idCountry;
		sessionData.idState   = stateData.idState;
		sessionData.idType    = stateData.idType;
		sessionData.errorCode = stateData.errorCode;

		this.ctx.storage.sql.exec(
			`INSERT OR REPLACE INTO sessions (sessionId, payloadHash, stateInt, data, createdAt) VALUES (?, ?, ?, ?, ?)`,
			sessionId,
			sessionData.payload ? sessionData.payload.substring(0, 64) : null,
			sessionData.stateInt || SESSION_STATE_IN_PROGRESS,
			JSON.stringify(sessionData),
			Date.now()
		);

		return true;
	}

	private isPayloadValidated(payloadHash: string): boolean {
		this.ensureInitialized();

		// Fix #7: Use indexed columns instead of LIKE on JSON blob
		const cursor = this.ctx.storage.sql.exec(
			`SELECT 1 FROM sessions WHERE payloadHash = ? AND stateInt = ?`,
			payloadHash,
			SESSION_STATE_SUCCESS
		);

		for (const _row of cursor) {
			return true;
		}
		return false;
	}

	private getById(sessionId: string): SessionData | null {
		this.ensureInitialized();

		const cursor = this.ctx.storage.sql.exec(
			`SELECT data FROM sessions WHERE sessionId = ?`,
			sessionId
		);

		for (const row of cursor) {
			return JSON.parse(row.data as string);
		}
		return null;
	}

	// ─── Payload Methods ───

	private storePayload(payloadHash: string, payload: string, creationTimestamp: number): void {
		const cursor = this.ctx.storage.sql.exec(
			`SELECT payloadHash FROM payloads WHERE payloadHash = ?`,
			payloadHash
		);
		let exists = false;
		for (const _row of cursor) {
			exists = true;
		}
		if (exists) return;

		this.ctx.storage.sql.exec(
			`INSERT INTO payloads (payloadHash, payload, creationTimestamp, createdAt) VALUES (?, ?, ?, ?)`,
			payloadHash, payload, creationTimestamp, Date.now()
		);
	}

	private isPayloadStored(payloadHash: string): boolean {
		const cursor = this.ctx.storage.sql.exec(
			`SELECT payloadHash FROM payloads WHERE payloadHash = ?`,
			payloadHash
		);
		for (const _row of cursor) {
			return true;
		}
		return false;
	}

	// ─── Request Session (per-request data like successKey/failKey) ───

	private storeRequestSession(sessionId: string, data: Record<string, any>): void {
		this.ensureInitialized();

		this.ctx.storage.sql.exec(
			`INSERT OR REPLACE INTO request_sessions (sessionId, data, createdAt) VALUES (?, ?, ?)`,
			sessionId,
			JSON.stringify(data),
			Date.now()
		);

		// Keep the table bounded (session cookies are valid for 20 minutes).
		this.ctx.storage.sql.exec(
			`DELETE FROM request_sessions WHERE createdAt < ?`,
			Date.now() - REQUEST_SESSION_RETENTION_TIME
		);
	}

	private getRequestSession(sessionId: string): Record<string, any> | null {
		this.ensureInitialized();

		const cursor = this.ctx.storage.sql.exec(
			`SELECT data FROM request_sessions WHERE sessionId = ?`,
			sessionId
		);
		for (const row of cursor) {
			return JSON.parse(row.data as string);
		}
		return null;
	}

	private async dispatchCallback(
		sessionData: SessionData,
		sessionStateInt: number,
		sessionId: string,
		errorCode: number,
		stepIp: number,
		idCountry: string,
		idState: string,
		idType: string
	): Promise<void> {
		try {
			const callbackData = new URLSearchParams({
				userData:        JSON.stringify(sessionData.userData),
				state:           STATE_MAP[sessionStateInt],
				stateInt:        String(sessionStateInt),
				sessionId:       sessionId,
				errorCode:       String(errorCode),
				deviceType:      sessionData.deviceType || '',
				stepId:          String(stepIp),
				idCountry:       idCountry,
				idState:         idState,
				idType:          idType,
				websiteHostname: sessionData.websiteHostname,
				ip:              sessionData.ip,
			});

			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort('callback_timeout'), CALLBACK_TIMEOUT_MS);

			try {
				const response = await fetch(sessionData.callbackUrl, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
					},
					body: callbackData.toString(),
					signal: controller.signal,
				});

				if (!response.ok) {
					throw new Error(`Callback returned HTTP ${response.status}`);
				}

				console.log('Callback data success!');
			} finally {
				clearTimeout(timeoutId);
			}
		} catch (err) {
			console.log('Callback dispatch error', { sessionId });
		}
	}
}
