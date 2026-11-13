<script lang="ts">
	import type { Mode } from '#lib/filters.js';

	let { mode }: { mode: Mode } = $props();
</script>

<!--
	Full-width hero. The picture is a CSS background (style-src 'self'): no
	inline style, so the strict CSP stays intact. Decorative: the text carries
	the meaning, the image has no alternative text to read.
-->
<section class="banner no-print mode-{mode}" aria-label="NOROSHI">
	<div class="picture" aria-hidden="true"></div>
	<div class="shade" aria-hidden="true"></div>
	<div class="content">
		<p class="kanji" lang="ja" title="狼煙, noroshi : le feu de signal">狼煙</p>
		<h1 class="wordmark">NOROSHI</h1>
		<p class="tagline">Le signal avant l'incendie.</p>
		<p class="subline">Catalogue de risques GRC et veille cyber. Traçables, européens, sans IA.</p>
	</div>
</section>

<style>
	.banner {
		position: relative;
		/* Full bleed, whatever the width of the page container. */
		width: 100vw;
		margin-left: calc(50% - 50vw);
		margin-top: -20px;
		margin-bottom: 24px;
		height: 280px;
		overflow: hidden;
		background: #111827;
		border-bottom: 4px solid var(--primary);
		transition: border-color 0.4s;
	}
	.banner.mode-cyber {
		border-bottom-color: var(--cyber);
	}
	.banner.mode-leaks {
		border-bottom-color: var(--leaks);
	}
	.picture {
		position: absolute;
		inset: 0;
		background-image: url('/banner.jpg');
		background-size: cover;
		/* Keeps the fire and the smoke column in view on every width. */
		background-position: 52% 60%;
		transform-origin: 48% 55%;
		animation: embers 28s ease-in-out infinite alternate;
	}
	.shade {
		position: absolute;
		inset: 0;
		background:
			linear-gradient(90deg, rgba(10, 14, 24, 0.86) 0%, rgba(10, 14, 24, 0.55) 38%, rgba(10, 14, 24, 0) 70%),
			linear-gradient(0deg, rgba(10, 14, 24, 0.45) 0%, rgba(10, 14, 24, 0) 45%);
	}
	.content {
		position: relative;
		max-width: 1400px;
		height: 100%;
		margin: 0 auto;
		padding: 0 20px;
		display: flex;
		flex-direction: column;
		justify-content: center;
		color: #f8fafc;
	}
	.kanji {
		margin: 0;
		font-size: 15px;
		letter-spacing: 6px;
		color: #fdba74;
		opacity: 0.9;
	}
	.wordmark {
		margin: 2px 0 6px;
		font-size: 54px;
		line-height: 1;
		font-weight: 800;
		letter-spacing: 10px;
		text-shadow: 0 2px 18px rgba(0, 0, 0, 0.6);
	}
	.tagline {
		margin: 0;
		font-size: 20px;
		font-weight: 600;
		color: #fed7aa;
	}
	.subline {
		margin: 8px 0 0;
		font-size: 13px;
		color: #cbd5e1;
		max-width: 460px;
	}
	@keyframes embers {
		from {
			transform: scale(1);
		}
		to {
			transform: scale(1.07);
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.picture {
			animation: none;
		}
	}
	@media (max-width: 760px) {
		.banner {
			height: 210px;
		}
		.picture {
			background-image: url('/banner-800.jpg');
			background-position: 58% 45%;
		}
		.shade {
			background: linear-gradient(90deg, rgba(10, 14, 24, 0.88) 0%, rgba(10, 14, 24, 0.45) 65%, rgba(10, 14, 24, 0.15) 100%);
		}
		.wordmark {
			font-size: 36px;
			letter-spacing: 6px;
		}
		.tagline {
			font-size: 16px;
		}
		.subline {
			font-size: 12px;
			max-width: 240px;
		}
	}
</style>
