import { describe, it, expect, vi } from 'vitest';
import { callDoJson } from '../../src/lib/do';

describe('callDoJson', () => {
	it('returns parsed JSON on success', async () => {
		const stub = {
			fetch: vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 })),
		};
		const result = await callDoJson<{ ok: boolean }>(stub as any, 'test', {});
		expect(result).toEqual({ ok: true });
	});

	it('throws on non-OK status', async () => {
		const stub = {
			fetch: vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 500 })),
		};
		await expect(callDoJson(stub as any, 'test', {})).rejects.toThrow(/failed/);
	});

	it('throws when response has error field', async () => {
		const stub = {
			fetch: vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: 'bad' }), { status: 200 })),
		};
		await expect(callDoJson(stub as any, 'test', {})).rejects.toThrow(/failed/);
	});

	it('includes HTTP status in the error message', async () => {
		const stub = {
			fetch: vi.fn().mockResolvedValue(new Response('error', { status: 503 })),
		};
		await expect(callDoJson(stub as any, 'test', {})).rejects.toThrow(/503/);
	});
});
