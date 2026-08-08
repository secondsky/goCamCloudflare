import type { getDoStub } from '../middleware/session';

type DoStub = ReturnType<typeof getDoStub>;

/**
 * Call a Durable Object action and parse the JSON response.
 * Throws on non-OK status or when the response contains an `error` field.
 * The error message includes the HTTP status (not the body, which may leak internals).
 */
export async function callDoJson<T>(
	stub: DoStub,
	action: string,
	body: Record<string, unknown>,
): Promise<T> {
	const response = await stub.fetch(
		new Request(`http://do/${action}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
		}),
	);

	let json: any = null;
	try {
		json = await response.json();
	} catch {
		throw new Error(`DO action "${action}" returned invalid JSON (HTTP ${response.status})`);
	}

	if (!response.ok || (json && typeof json === 'object' && typeof json.error !== 'undefined')) {
		throw new Error(`DO action "${action}" failed (HTTP ${response.status})`);
	}

	return json as T;
}
