import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
	// The `cloudflareTest()` plugin registers the Workers runtime as a Vitest
	// pool so integration tests (DO, fetch handler) can run under
	// `npm run test:workers` (which sets --pool=workers). Pure-logic unit tests
	// run in the default `forks` pool below — they do not need this plugin,
	// but it must be installed for the workers pool to resolve bindings.
	plugins: [
		cloudflareTest({
			wrangler: { configPath: './wrangler.jsonc' },
		}),
	],
	test: {
		// Unit tests for pure-logic modules run in the default node pool.
		// Integration tests use the workers pool via the `test:workers`
		// script which sets --pool=workers.
		pool: 'forks',
		include: ['test/**/*.test.ts'],
	},
});
