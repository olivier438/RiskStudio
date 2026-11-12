import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// Fully static build: Apache on the Infomaniak shared hosting serves `build/`,
// and the PHP API answers under /api. No Node.js process runs in production.
export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			adapter: adapter({ pages: 'build', assets: 'build', fallback: undefined, strict: true }),
			// Strict CSP without 'unsafe-inline': SvelteKit hashes its own inline
			// bootstrap script. frame-ancestors cannot live in a <meta> tag, so it
			// is sent as a real header by static/.htaccess.
			csp: {
				mode: 'hash',
				directives: {
					'default-src': ['self'],
					'script-src': ['self'],
					// 'unsafe-hashes' + one hash: allows only SvelteKit's route announcer
					// style attribute (accessibility), nothing else.
					'style-src': ['self', 'unsafe-hashes', 'sha256-S8qMpvofolR8Mpjy4kQvEm7m1q8clzU4dfDH0AmvZjo='],
					'img-src': ['self', 'data:'],
					'font-src': ['self'],
					'connect-src': ['self'],
					'object-src': ['none'],
					'base-uri': ['self'],
					'form-action': ['self']
				}
			}
		})
	],
	server: {
		// Dev only: forward API calls to `php -S 127.0.0.1:8080` (see Makefile).
		proxy: {
			'/api': 'http://127.0.0.1:8080'
		}
	}
});
