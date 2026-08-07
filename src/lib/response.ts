/**
 * Standard response format helpers.
 * Direct port — no Node.js dependencies, works as-is.
 */
export class AvsResponse {

	static successResponse(data: Record<string, any> = {}): { content: Record<string, any> } {
		return {
			content: { ...data, success: 1 },
		};
	}

	static errorResponse(code: number, msg: string): { error: { code: number; msg: string } } {
		return {
			error: {
				code: code,
				msg: msg,
			},
		};
	}
}
