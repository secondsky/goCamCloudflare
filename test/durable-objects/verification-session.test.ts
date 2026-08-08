import { describe, it, expect, beforeEach } from 'vitest';
// `env` and the other test helpers come from the `cloudflare:test` virtual
// module, which the `cloudflareTest()` Vitest plugin resolves. The plugin runs
// every test file in this project under the Workers runtime (workerd) via
// Miniflare, so no `@vitest-environment` pragma is needed — the whole file
// already executes inside workerd.
import { env } from 'cloudflare:test';
import { AvsEncryption } from '../../src/lib/encryption';
import { hkdfDerive } from '../../src/lib/crypto-utils';
import {
	SESSION_STATE_IN_PROGRESS,
	SESSION_STATE_SUCCESS,
	SESSION_STATE_LINK_EXPIRED,
	SESSION_STATE_LINK_ALREADY_USED,
} from '../../src/durable-objects/verification-session';

// ─── Test key derivation ───
// The DO derives its AES key from `env.ENCRYPTION_KEY`. In the workers pool
// that binding is provided by vitest.config.ts (`miniflare.bindings`), set to
// `'a'.repeat(32)` — the same passphrase as `TEST_PASSPHRASE` in
// `test/helpers/crypto-keys.ts`. Derive the matching AES subkey here so we
// can encrypt payloads the DO will successfully decrypt, and decrypt the
// payloads the DO returns.
const TEST_KEY_STRING = 'a'.repeat(32);
const HKDF_CONTEXT = 'avs/aes/v1';
const aesKeyPromise: Promise<Uint8Array> = hkdfDerive(TEST_KEY_STRING, HKDF_CONTEXT, 32);

// ─── Helpers ───

interface TestPayload {
	creationTimestamp: number;
	callbackUrl: string;
	userIpStr: string;
	userIpCountry: string;
	userIpState: string;
	websiteHostname: string;
	verificationVersion: number;
	userData: Record<string, unknown>;
	httpParamList: { userAgent: string };
	linkBack: string;
}

function makePayload(overrides: Partial<TestPayload> = {}): TestPayload {
	return {
		creationTimestamp: Date.now(),
		// Empty callback URL → the DO will NOT schedule a real fetch dispatch,
		// keeping tests side-effect-free.
		callbackUrl: '',
		userIpStr: '1.2.3.4',
		userIpCountry: 'US',
		userIpState: 'CA',
		websiteHostname: 'example.com',
		verificationVersion: 1,
		userData: {},
		httpParamList: { userAgent: 'test-agent' },
		linkBack: '/',
		...overrides,
	};
}

async function encryptPayload(payload: TestPayload): Promise<string> {
	const aesKey = await aesKeyPromise;
	return AvsEncryption.encryptObject(payload, aesKey);
}

/**
 * Mint a DO stub backed by a fresh unique name. Each test gets its own DO
 * instance so SQLite state from one test cannot leak into another (the DO
 * keys its sessions table by nothing — every name is a separate database).
 */
function getStub(suffix: string) {
	const id = env.VERIFICATION_SESSION.idFromName(suffix);
	return env.VERIFICATION_SESSION.get(id);
}

async function doPost<T = any>(stub: ReturnType<typeof getStub>, action: string, body: Record<string, unknown>): Promise<T> {
	const response = await stub.fetch(`https://do/${action}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body),
	});
	return response.json() as Promise<T>;
}

// ─── Tests ───

// Counter shared across tests so each test gets a unique DO name without the
// author having to thread an index through every assertion. Reset is
// unnecessary: the counter only goes up, so names never collide.
let doCounter = 0;

beforeEach(() => {
	doCounter++;
});

function uniqueName(label: string): string {
	return `${label}-${doCounter}`;
}

describe('VerificationSession Durable Object', () => {
	it('1. start creates an in-progress session', async () => {
		const stub = getStub(uniqueName('start-ok'));
		const payload = await encryptPayload(makePayload());

		const result = await doPost<{ sessionState: number; sessionId: string }>(stub, 'start', { payload });

		expect(result.sessionState).toBe(SESSION_STATE_IN_PROGRESS);
		// sessionId must be a UUID (36 chars, dashed).
		expect(result.sessionId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
	});

	it('2. start with same payload returns LINK_ALREADY_USED', async () => {
		const stub = getStub(uniqueName('start-reuse'));
		const payload = await encryptPayload(makePayload());

		const first = await doPost<{ sessionState: number }>(stub, 'start', { payload });
		expect(first.sessionState).toBe(SESSION_STATE_IN_PROGRESS);

		// Reuse the EXACT same ciphertext string → same payloadHash → the DO
		// recognises it as a replayed link and refuses to start again.
		const second = await doPost<{ sessionState: number }>(stub, 'start', { payload });
		expect(second.sessionState).toBe(SESSION_STATE_LINK_ALREADY_USED);
	});

	it('3. start with expired payload returns LINK_EXPIRED', async () => {
		const stub = getStub(uniqueName('start-expired'));
		// 20 minutes ago — past the 10-minute PAYLOAD_EXPIRATION_TIME window.
		const expiredPayload = await encryptPayload(makePayload({ creationTimestamp: Date.now() - 20 * 60 * 1000 }));

		const result = await doPost<{ sessionState: number }>(stub, 'start', { payload: expiredPayload });

		expect(result.sessionState).toBe(SESSION_STATE_LINK_EXPIRED);
	});

	it('4. end transitions to a terminal state and returns an encrypted payload', async () => {
		const stub = getStub(uniqueName('end-ok'));
		const payload = await encryptPayload(makePayload());

		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });

		const endResult = await doPost<{ payload: string } | null>(stub, 'end', {
			sessionId: start.sessionId,
			sessionStateInt: SESSION_STATE_SUCCESS,
			stepIp: 5,
			errorCode: 0,
			idCountry: 'US',
			idState: 'CA',
			idType: 'drivers-license',
		});

		expect(endResult).not.toBeNull();
		expect(typeof (endResult as { payload: string }).payload).toBe('string');
	});

	it('5. double-end returns the existing payload instead of re-ending', async () => {
		const stub = getStub(uniqueName('end-twice'));
		const payload = await encryptPayload(makePayload());

		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		const endBody = {
			sessionId: start.sessionId,
			sessionStateInt: SESSION_STATE_SUCCESS,
			stepIp: 5,
			errorCode: 0,
			idCountry: 'US',
			idState: 'CA',
			idType: 'drivers-license',
		};

		const first = await doPost<{ payload: string } | null>(stub, 'end', endBody);
		expect(first).not.toBeNull();

		// Second end must NOT throw, NOT return null, and NOT mutate state — it
		// hands back the re-encrypted existing terminal payload.
		const second = await doPost<{ payload: string } | null>(stub, 'end', endBody);
		expect(second).not.toBeNull();
		expect(typeof (second as { payload: string }).payload).toBe('string');
	});

	it('6. end on an expired (non-eligible) session returns null', async () => {
		const stub = getStub(uniqueName('end-expired'));
		const expiredPayload = await encryptPayload(makePayload({ creationTimestamp: Date.now() - 20 * 60 * 1000 }));

		const start = await doPost<{ sessionId: number; sessionState: number }>(stub, 'start', { payload: expiredPayload });
		expect(start.sessionState).toBe(SESSION_STATE_LINK_EXPIRED);

		// The non-eligible-state guard blocks ending anything that is not
		// IN_PROGRESS, so end returns null.
		const endResult = await doPost<{ payload: string } | null>(stub, 'end', {
			sessionId: start.sessionId as unknown as string,
			sessionStateInt: SESSION_STATE_SUCCESS,
			stepIp: 0,
			errorCode: 0,
			idCountry: '',
			idState: '',
			idType: '',
		});

		expect(endResult).toBeNull();
	});

	it('7. updateState on a terminal session returns success:false', async () => {
		const stub = getStub(uniqueName('update-terminal'));
		const payload = await encryptPayload(makePayload());

		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });
		await doPost(stub, 'end', {
			sessionId: start.sessionId,
			sessionStateInt: SESSION_STATE_SUCCESS,
			stepIp: 5,
			errorCode: 0,
			idCountry: 'US',
			idState: 'CA',
			idType: 'drivers-license',
		});

		const result = await doPost<{ success: boolean }>(stub, 'updateState', {
			sessionId: start.sessionId,
			stateData: { stepId: 3, idCountry: 'US', idState: 'NY', idType: 'passport', errorCode: 0 },
		});

		expect(result.success).toBe(false);
	});

	it('8. isPayloadValidated is false before end, true after', async () => {
		const stub = getStub(uniqueName('validated'));
		const payload = await encryptPayload(makePayload());
		const payloadHash = await AvsEncryption.computePayloadHash(payload);

		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });

		const before = await doPost<{ isValidated: boolean }>(stub, 'isPayloadValidated', { payloadHash });
		expect(before.isValidated).toBe(false);

		await doPost(stub, 'end', {
			sessionId: start.sessionId,
			sessionStateInt: SESSION_STATE_SUCCESS,
			stepIp: 5,
			errorCode: 0,
			idCountry: 'US',
			idState: 'CA',
			idType: 'drivers-license',
		});

		const after = await doPost<{ isValidated: boolean }>(stub, 'isPayloadValidated', { payloadHash });
		expect(after.isValidated).toBe(true);
	});

	it('9. storeRequestSession / getRequestSession round-trip', async () => {
		const stub = getStub(uniqueName('req-session'));
		const sessionId = 'req-' + doCounter;
		const data = { successKey: 'abc', failKey: 'def' };

		const storeResult = await doPost<{ success: boolean }>(stub, 'storeRequestSession', { sessionId, data });
		expect(storeResult.success).toBe(true);

		const fetched = await doPost<typeof data | null>(stub, 'getRequestSession', { sessionId });
		expect(fetched).toEqual(data);
	});

	it('10. getSession returns null for an unknown id', async () => {
		const stub = getStub(uniqueName('get-unknown'));
		const unknownId = crypto.randomUUID();

		const result = await doPost<unknown>(stub, 'getSession', { sessionId: unknownId });

		expect(result).toBeNull();
	});

	it('11. end strips PII from the returned payload and stamps verificationResult', async () => {
		const stub = getStub(uniqueName('pii-strip'));
		const payload = await encryptPayload(makePayload({
			userIpStr: '9.9.9.9',
			userIpCountry: 'US',
			userIpState: 'CA',
			callbackUrl: 'https://partner.example.com/cb',
		}));

		const start = await doPost<{ sessionId: string }>(stub, 'start', { payload });

		const endResult = await doPost<{ payload: string }>(stub, 'end', {
			sessionId: start.sessionId,
			sessionStateInt: SESSION_STATE_SUCCESS,
			stepIp: 5,
			errorCode: 0,
			idCountry: 'US',
			idState: 'CA',
			idType: 'drivers-license',
		});

		// Decrypt with the same key the DO used to encrypt the result.
		const aesKey = await aesKeyPromise;
		const decrypted = await AvsEncryption.decryptString(endResult.payload, aesKey);

		// PII fields must be blanked — the result payload becomes the
		// isAgeVerified cookie value, so it must never carry the user's IP
		// or geo data.
		expect(decrypted.callbackUrl).toBe('');
		expect(decrypted.userIpStr).toBe('');
		expect(decrypted.userIpCountry).toBe('');
		expect(decrypted.userIpState).toBe('');

		// The verification result block must reflect the terminal state.
		expect(decrypted.verificationResult).toBeDefined();
		expect(decrypted.verificationResult!.stateInt).toBe(SESSION_STATE_SUCCESS);
	});
});
