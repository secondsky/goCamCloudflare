import { DurableObject } from 'cloudflare:workers';
import { AvsEncryption } from '../lib/encryption';
import { hkdfDerive } from '../lib/crypto-utils';
import { LEAKED_EXAMPLE_KEY } from '../config';
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
const MAX_CALLBACK_ATTEMPTS = 5;

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
	callbackStatus?: 'pending' | 'sent' | 'failed';
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
	 *
	 * Validates the raw key the same way getConfig does — presence, 32-byte
	 * length, and the leaked-key blocklist — so a misconfigured DO cannot
	 * silently derive a predictable key from the string "undefined".
	 */
	private async getAesKey(): Promise<Uint8Array> {
		if (!this._aesKeyPromise) {
			const raw = this.env.ENCRYPTION_KEY;
			if (!raw) {
				throw new Error('ENCRYPTION_KEY is not set in the DO environment');
			}
			const keyBytes = new TextEncoder().encode(raw);
			if (keyBytes.byteLength !== 32) {
				throw new Error(`DO ENCRYPTION_KEY must be exactly 32 bytes (got ${keyBytes.byteLength})`);
			}
			if (raw === LEAKED_EXAMPLE_KEY) {
				throw new Error('DO ENCRYPTION_KEY matches the known leaked example key');
			}
			this._aesKeyPromise = hkdfDerive(raw, 'avs/aes/v1', 32);
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
				createdAt INTEGER NOT NULL,
				callbackStatus TEXT DEFAULT 'pending',
				callbackAttempts INTEGER DEFAULT 0
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
			// Migration: add columns for pre-existing DO instances whose
			// sessions table predates these fields. Wrapped in try/catch
			// because the columns already exist on a fresh DO (created above).
			try {
				this.ctx.storage.sql.exec(`ALTER TABLE sessions ADD COLUMN callbackStatus TEXT DEFAULT 'pending'`);
			} catch {
				// Column already exists — nothing to do.
			}
			try {
				this.ctx.storage.sql.exec(`ALTER TABLE sessions ADD COLUMN callbackAttempts INTEGER DEFAULT 0`);
			} catch {
				// Column already exists — nothing to do.
			}
			// Index callbackStatus so the alarm scan is cheap.
			try {
				this.ctx.storage.sql.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_callbackStatus ON sessions (callbackStatus)`);
			} catch {
				// Index may already exist.
			}
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
					const result = await this.updateState(body.sessionId, body.stateData);
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
					await this.storeRequestSession(body.sessionId, body.data);
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
		const payloadHash = await AvsEncryption.computePayloadHash(payload);

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
			ipState:             payloadParsed.userIpState ?? '',
			websiteHostname:     payloadParsed.websiteHostname,
			verificationVersion: payloadParsed.verificationVersion ?? 0,
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
			linkBack:     payloadParsed.linkBack ?? '',
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
	): Promise<{ payload: string; stateInt: number } | null> {
		this.ensureInitialized();

		const aesKey = await this.getAesKey();
		const sessionData = this.getById(sessionId);
		if (!sessionData) return null;

		// Terminal-state guard: an already-success or already-fail session must
		// not be re-ended. Re-ending would dispatch a duplicate partner callback
		// and mint a second isAgeVerified cookie from the same verification.
		// Return the existing result payload (re-encrypted) instead.
		if (sessionData.stateInt === SESSION_STATE_SUCCESS || sessionData.stateInt === SESSION_STATE_FAILED) {
			const decryptedPayload = await AvsEncryption.decryptString(sessionData.payload, aesKey);
			// Match the normal end path: update userData and strip PII.
			decryptedPayload.userData      = sessionData.userData;
			decryptedPayload.callbackUrl   = '';
			decryptedPayload.userIpStr     = '';
			decryptedPayload.userIpCountry = '';
			decryptedPayload.userIpState   = '';
			decryptedPayload.verificationResult = {
				state:     STATE_MAP[sessionData.stateInt],
				stateInt:  sessionData.stateInt,
				sessionId,
				errorCode: sessionData.errorCode || 0,
			};
			return { payload: await AvsEncryption.encryptObject(decryptedPayload, aesKey), stateInt: sessionData.stateInt };
		}

		// Non-eligible state guard: a session in LINK_EXPIRED or
		// LINK_ALREADY_USED must not be transitioned to SUCCESS/FAILED.
		// Only an IN_PROGRESS session can be ended. This prevents expired or
		// reused links from being completed.
		if (sessionData.stateInt !== SESSION_STATE_IN_PROGRESS) {
			return null;
		}

		sessionData.stateInt        = sessionStateInt;
		sessionData.state           = STATE_MAP[sessionStateInt];
		sessionData.stepIp          = stepIp;
		sessionData.idCountry       = idCountry;
		sessionData.idState         = idState;
		sessionData.idType          = idType;
		sessionData.errorCode       = errorCode;
		sessionData.callbackStatus  = 'pending';

		// Persist the terminal state to SQLite BEFORE scheduling the callback
		// dispatch. If the DO is evicted between the waitUntil dispatch and the
		// SQL write, the terminal state would be lost — /result/isSuccess would
		// report false forever for a verification the user saw succeed.
		// Use UPDATE (not INSERT OR REPLACE) to preserve createdAt and
		// callbackAttempts from the existing row. The row provably exists
		// because getById returned it above and the terminal-state guard
		// guarantees it hasn't been deleted.
		this.ctx.storage.sql.exec(
			`UPDATE sessions SET payloadHash = ?, stateInt = ?, data = ?, callbackStatus = ? WHERE sessionId = ?`,
			sessionData.payload ? await AvsEncryption.computePayloadHash(sessionData.payload) : null,
			sessionStateInt,
			JSON.stringify(sessionData),
			'pending',
			sessionId
		);

		// Audit log
		this.ctx.storage.sql.exec(
			`INSERT INTO audit_log (sessionId, event, detail, timestamp) VALUES (?, ?, ?, ?)`,
			sessionId,
			'session_ended',
			JSON.stringify({ state: STATE_MAP[sessionStateInt], errorCode }),
			Date.now()
		);

		// Dispatch callback in background so user-facing completion is not
		// blocked. Runs only after the terminal state is durably persisted.
		if (sessionData.callbackUrl) {
			this.ctx.waitUntil(
				this.dispatchCallback(sessionData, sessionStateInt, sessionId, errorCode, stepIp, idCountry, idState, idType)
			);
			// Schedule a retry alarm in 60s as a fallback for failed/pending callbacks.
			try {
				this.ctx.storage.setAlarm(Date.now() + 60_000);
			} catch (err) {
				console.error('Failed to schedule callback retry alarm', err);
			}
		}

		// Build result payload (same format as original)
		const decryptedPayload = await AvsEncryption.decryptString(sessionData.payload, aesKey);
		decryptedPayload.userData           = sessionData.userData;
		// Strip PII from the result payload. This value is stored in the
		// isAgeVerified cookie on the client browser and returned to the
		// partner — it must not contain the user's IP address or geo data.
		decryptedPayload.callbackUrl        = '';
		decryptedPayload.userIpStr          = '';
		decryptedPayload.userIpCountry      = '';
		decryptedPayload.userIpState        = '';
		decryptedPayload.verificationResult = {
			state:     STATE_MAP[sessionStateInt],
			stateInt:  sessionStateInt,
			sessionId,
			errorCode,
		};

		return {
			payload: await AvsEncryption.encryptObject(decryptedPayload, aesKey),
			stateInt: sessionStateInt,
		};
	}

	private async updateState(sessionId: string, stateData: StateData): Promise<boolean> {
		this.ensureInitialized();

		const sessionData = this.getById(sessionId);
		if (!sessionData) return false;

		// Terminal-state guard: do not mutate a session that has already
		// reached SUCCESS or FAILED. Overwriting a terminal row would
		// corrupt the audit/billing data and reset callbackStatus to the
		// schema default ('pending'), triggering duplicate partner callbacks.
		if (sessionData.stateInt === SESSION_STATE_SUCCESS || sessionData.stateInt === SESSION_STATE_FAILED) {
			return false;
		}

		sessionData.stepIp    = stateData.stepId;
		sessionData.idCountry = stateData.idCountry;
		sessionData.idState   = stateData.idState;
		sessionData.idType    = stateData.idType;
		sessionData.errorCode = stateData.errorCode;

		// Use UPDATE (not INSERT OR REPLACE) so we preserve the callbackStatus
		// column and createdAt from the existing row.
		this.ctx.storage.sql.exec(
			`UPDATE sessions SET payloadHash = ?, stateInt = ?, data = ? WHERE sessionId = ?`,
			sessionData.payload ? await AvsEncryption.computePayloadHash(sessionData.payload) : null,
			sessionData.stateInt || SESSION_STATE_IN_PROGRESS,
			JSON.stringify(sessionData),
			sessionId
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
			try {
				return JSON.parse(row.data as string);
			} catch (e) {
				console.error('Corrupt session row for', sessionId, e);
				return null;
			}
		}
		return null;
	}

	// ─── Payload Methods ───

	private storePayload(payloadHash: string, payload: string, creationTimestamp: number): void {
		this.ensureInitialized();
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
		this.ensureInitialized();
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

	private async storeRequestSession(sessionId: string, data: Record<string, any>): Promise<void> {
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
			try {
				return JSON.parse(row.data as string);
			} catch (e) {
				console.error('Corrupt request_session row for', sessionId, e);
				return null;
			}
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
					// SSRF defense: never follow redirects. A partner callback URL
					// that responds 3xx to an internal address (e.g. the cloud
					// metadata endpoint http://169.254.169.254/...) would otherwise
					// be silently followed by the Workers default (`redirect:
					// 'follow'`), leaking session data to an internal target.
					redirect: 'manual',
				});

				// With `redirect: 'manual'`, any 3xx is the raw redirect response.
				// Reject it explicitly as a failure — do NOT follow the Location.
				if (response.status >= 300 && response.status < 400) {
					throw new Error(`Callback returned redirect ${response.status} — not following (SSRF defense)`);
				}

				if (!response.ok) {
					throw new Error(`Callback returned HTTP ${response.status}`);
				}

				this.updateCallbackStatus(sessionId, 'sent');
				console.log('Callback data success!');
			} finally {
				clearTimeout(timeoutId);
			}
		} catch (err) {
			this.updateCallbackStatus(sessionId, 'failed');
			console.log('Callback dispatch error', { sessionId });
		}
	}

	/**
	 * Update the callbackStatus on a session row — both in the indexed
	 * `callbackStatus` column (for the alarm scan) and inside the `data`
	 * JSON blob (so getById round-trips it). Increments callbackAttempts on
	 * every call so the alarm handler can cap retries. No-op if the session
	 * is gone.
	 */
	private updateCallbackStatus(sessionId: string, status: 'pending' | 'sent' | 'failed'): void {
		this.ensureInitialized();
		const sessionData = this.getById(sessionId);
		if (!sessionData) return;
		sessionData.callbackStatus = status;
		this.ctx.storage.sql.exec(
			`UPDATE sessions SET data = ?, callbackStatus = ?, callbackAttempts = callbackAttempts + 1 WHERE sessionId = ?`,
			JSON.stringify(sessionData),
			status,
			sessionId
		);
	}

	/**
	 * Alarm handler — used as a fallback to retry callbacks that never
	 * reached 'sent' (e.g. the waitUntil task was evicted, or the partner
	 * endpoint was temporarily unavailable). Scheduled 60s after endSession.
	 *
	 * Retries are capped at MAX_CALLBACK_ATTEMPTS per session. If any
	 * retryable session remains after this firing, the alarm is re-armed
	 * so callbacks are not abandoned after a single retry.
	 */
	async alarm(): Promise<void> {
		this.ensureInitialized();
		let needRearm = false;
		const cursor = this.ctx.storage.sql.exec(
			`SELECT sessionId, data, callbackAttempts FROM sessions WHERE callbackStatus IN ('failed', 'pending')`
		);
		for (const row of cursor) {
			const attempts = (row.callbackAttempts as number) || 0;
			if (attempts >= MAX_CALLBACK_ATTEMPTS) continue;

			let sessionData: SessionData;
			try {
				sessionData = JSON.parse(row.data as string) as SessionData;
			} catch (e) {
				// Skip corrupt rows so one bad row doesn't abort the sweep.
				console.error('Corrupt session row in alarm sweep', row.sessionId, e);
				continue;
			}
			// Only retry terminal sessions (success/fail) that have a callback URL.
			if (
				sessionData.callbackUrl &&
				(sessionData.stateInt === SESSION_STATE_SUCCESS || sessionData.stateInt === SESSION_STATE_FAILED)
			) {
				needRearm = true;
				await this.dispatchCallback(
					sessionData,
					sessionData.stateInt,
					sessionData.sessionId,
					sessionData.errorCode || 0,
					sessionData.stepIp || 0,
					sessionData.idCountry || '',
					sessionData.idState || '',
					sessionData.idType || ''
				);
			}
		}

		// Re-arm the alarm if there are still sessions that may need another
		// retry (they are below the attempt cap and their callback may fail
		// again on this attempt).
		if (needRearm) {
			try {
				this.ctx.storage.setAlarm(Date.now() + 60_000);
			} catch (err) {
				console.error('Failed to re-schedule callback retry alarm', err);
			}
		}
	}
}
