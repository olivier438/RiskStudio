<script lang="ts">
	import '../app.css';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();
</script>

<svelte:head>
	<link rel="icon" href="/rs.jpg" />
</svelte:head>

<div class="container">
	{@render children()}
</div>
