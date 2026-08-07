/**
 * Shared types for decrypted verification payloads.
 *
 * `decryptString` previously returned `any`, so no field was type-checked at
 * call sites. This module defines `DecryptedPayload` plus a runtime type guard
 * `isDecryptedPayload` that callers can use to validate untrusted decoded JSON
 * before relying on its shape.
 */

export interface VerificationResult {
	state: string;
	stateInt: number;
	sessionId: string;
	errorCode: number;
}

export interface DecryptedPayload {
	userData: Record<string, any>;
	httpUserAgent?: string;
	websiteHostname: string;
	httpParamList?: Record<string, any>;
	verificationVersion?: number;
	linkBack?: string;
	userIpCountry: string;
	userIpState?: string;
	userIpStr: string;
	callbackUrl: string;
	creationTimestamp: number;
	verificationResult?: VerificationResult;
}

/**
 * Runtime type guard for `DecryptedPayload`.
 *
 * NOTE: this is a loose check — it returns true if ANY of the key fields is
 * present with the expected type (the conditions are OR'd). This is acceptable
 * as a first-pass sanity check over already-decrypted JSON. A stricter
 * (AND'd) version would reject payloads missing optional fields, which is
 * undesirable until all producers are audited for shape consistency.
 */
export function isDecryptedPayload(v: unknown): v is DecryptedPayload {
	if (typeof v !== 'object' || v === null) return false;
	const obj = v as Record<string, unknown>;
	return (
		typeof obj.userData === 'object' ||
		typeof obj.websiteHostname === 'string' ||
		typeof obj.callbackUrl === 'string' ||
		typeof obj.creationTimestamp === 'number'
	);
}
