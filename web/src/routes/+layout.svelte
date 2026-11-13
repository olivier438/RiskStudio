<script lang="ts">
	import '../app.css';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();
</script>

<svelte:head>
	<link rel="icon" type="image/png" href="/favicon.png" />
	<link rel="apple-touch-icon" href="/apple-touch-icon.png" />
	<!-- Link previews (LinkedIn, messaging apps): absolute URLs are required. -->
	<meta property="og:type" content="website" />
	<meta property="og:site_name" content="NOROSHI" />
	<meta property="og:title" content="NOROSHI | Catalogue GRC et veille cyber" />
	<meta
		property="og:description"
		content="Catalogue de risques GRC mappé sur ISO 27001, NIS2, DORA, CRA, CyFun et NIST CSF, et veille cyber traçable, sans IA."
	/>
	<meta property="og:image" content="https://www.noroshi.be/og.jpg" />
	<meta property="og:image:width" content="1200" />
	<meta property="og:image:height" content="630" />
	<meta property="og:image:alt" content="Signal de fumée noroshi allumé sur une crête au crépuscule" />
	<meta name="twitter:card" content="summary_large_image" />
</svelte:head>

<div class="container">
	{@render children()}
</div>
