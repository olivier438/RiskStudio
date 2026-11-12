<script lang="ts">
	let { env }: { env: 'IT' | 'OT' | 'BOTH' } = $props();
</script>

{#if env === 'OT'}
	<span class="tag tag-ot">⚙️ OT</span>
{:else if env === 'BOTH'}
	<span class="tag tag-both">💻⚙️ IT/OT</span>
{:else}
	<span class="tag tag-it">💻 IT</span>
{/if}
