<script lang="ts">
	import type { Risk } from '#lib/api.js';

	let { controls }: { controls: Risk['controls'] } = $props();

	// Primary frameworks shown inline, the larger crosswalks folded below.
	const INLINE = [
		{ code: 'ISO27001_2022', label: '📋 ISO' },
		{ code: 'NIS2', label: '🇪🇺 NIS2' },
		{ code: 'DORA', label: '🏦 DORA' },
		{ code: 'CRA', label: '🔒 CRA' }
	];
	const FOLDED = [
		{ code: 'CYFUN_2023', label: 'CyFun' },
		{ code: 'NIST_CSF_2', label: 'NIST CSF' }
	];

	const byFramework = $derived.by(() => {
		const map = new Map<string, Risk['controls']>();
		for (const c of controls) map.set(c.framework, [...(map.get(c.framework) ?? []), c]);
		return map;
	});
	const folded = $derived(FOLDED.filter((f) => byFramework.has(f.code)));
</script>

{#each INLINE as fw (fw.code)}
	{#if byFramework.has(fw.code)}
		<div class="fw-line">
			<b>{fw.label} :</b>
			{#each byFramework.get(fw.code) ?? [] as c, i (c.ref)}
				<span class:derived={c.source === 'crosswalk'} title={c.source === 'crosswalk' ? 'Dérivé via la correspondance ISO' : 'Mapping éditorial'}
					>{c.ref}</span
				>{i < (byFramework.get(fw.code)?.length ?? 0) - 1 ? ', ' : ''}
			{/each}
		</div>
	{/if}
{/each}

{#if folded.length}
	<details class="folded">
		<summary>{folded.map((f) => `${f.label} (${byFramework.get(f.code)?.length})`).join(' · ')}</summary>
		{#each folded as fw (fw.code)}
			<div class="fw-line">
				<b>{fw.label} :</b>
				{(byFramework.get(fw.code) ?? []).map((c) => c.ref).join(', ')}
			</div>
		{/each}
	</details>
{/if}

{#if controls.length === 0}
	<small class="muted">-</small>
{/if}

<style>
	.fw-line {
		font-size: 11px;
		line-height: 1.7;
	}
	.derived {
		color: #94a3b8;
		font-style: italic;
	}
	.folded {
		font-size: 11px;
		margin-top: 4px;
		color: var(--muted);
	}
	.folded summary {
		cursor: pointer;
		color: var(--primary);
	}
	@media print {
		.folded:not([open]) {
			display: none;
		}
	}
</style>
