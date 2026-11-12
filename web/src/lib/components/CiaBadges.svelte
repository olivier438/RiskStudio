<script lang="ts">
	import type { Risk } from '#lib/api.js';

	let { cia }: { cia: Risk['cia'] } = $props();
</script>

{#if cia.confidentiality}<span class="cia-badge cia-c" title="Confidentiality">C</span>{/if}
{#if cia.integrity}<span class="cia-badge cia-i" title="Integrity">I</span>{/if}
{#if cia.availability}<span class="cia-badge cia-a" title="Availability">A</span>{/if}
