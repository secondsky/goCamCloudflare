import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
	// The `cloudflareTest()` plugin registers the Workers runtime as a Vitest
	// pool so integration tests (DO, fetch handler) can run under
	// `npm run test:workers` (which sets --pool=workers). Pure-logic unit tests
	// run in the default `forks` pool below — they do not need this plugin,
	// but it must be installed for the workers pool to resolve bindings.
	//
	// The options passed to `cloudflareTest()` ARE the workers pool options
	// (wrangler config + miniflare overrides). In Vitest 4 the legacy
	// `test.poolOptions.workers` shape was removed, so pool-specific settings
	// must live here, not under `test`.
	plugins: [
		cloudflareTest({
			wrangler: { configPath: './wrangler.jsonc' },
			miniflare: {
				// `wrangler.jsonc` does not list ENCRYPTION_KEY (it is a secret).
				// Provide it here so integration tests against the DO can derive
				// the same AES subkey the production code derives at runtime.
				// The passphrase matches `TEST_PASSPHRASE` in
				// `test/helpers/crypto-keys.ts`, so payloads encrypted in tests
				// with `getTestKeys()` decrypt inside the DO without any
				// per-test plumbing.
				bindings: {
					ENCRYPTION_KEY: 'a'.repeat(32),
					ENCRYPTION_ALGORITHM: 'AES-GCM',
				},
			},
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
