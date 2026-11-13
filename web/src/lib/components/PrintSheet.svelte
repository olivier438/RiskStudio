<script lang="ts">
	import type { IntelItem, Leak, Risk } from '#lib/api.js';
	import type { Mode } from '#lib/filters.js';
	import { count, dateAndTime, LEAK_TYPE_LABEL, SEVERITY_LABEL } from '#lib/format.js';
	import type { RiskEdits } from '#lib/selection.svelte.js';

	let {
		mode,
		risks,
		intel,
		leaks,
		edits
	}: {
		mode: Mode;
		risks: Risk[];
		intel: IntelItem[];
		leaks: Leak[];
		edits: Map<string, RiskEdits>;
	} = $props();

	const TITLE: Record<Mode, string> = {
		grc: 'Sélection de risques GRC',
		cyber: 'Sélection d’alertes cyber',
		leaks: 'Sélection de fuites de données'
	};

	const refs = (r: Risk, fw: string) =>
		r.controls
			.filter((c) => c.framework === fw)
			.map((c) => c.ref)
			.join(', ');
</script>

<!-- Printed instead of the interactive table: every selected item, all pages. -->
<section class="print-only sheet">
	<h1>🛡️ NOROSHI : {TITLE[mode]}</h1>
	<p class="meta">Export du {dateAndTime(new Date().toISOString())}</p>

	{#if mode === 'grc'}
		{#each risks as r (r.code)}
			{@const e = edits.get(r.code)}
			<article>
				<h2>{r.code} | {e?.title ?? r.title} <small>Impact {r.impact}/5 · {r.environment}</small></h2>
				<p><b>Scénario :</b> {e?.scenario ?? r.scenario}</p>
				<p><b>Mesures :</b> {e?.measures ?? r.measures}</p>
				<p class="refs">
					{r.category.name_fr} · {r.threat} · ISO {refs(r, 'ISO27001_2022') || '-'} · NIS2 {refs(r, 'NIS2') || '-'}
					{#if refs(r, 'DORA')}· DORA {refs(r, 'DORA')}{/if}
					{#if refs(r, 'CRA')}· CRA {refs(r, 'CRA')}{/if}
				</p>
			</article>
		{/each}
	{:else if mode === 'cyber'}
		{#each intel as it (it.id)}
			<article>
				<h2>
					{it.title}
					<small>{it.critical ? 'CRITIQUE' : it.severity ? SEVERITY_LABEL[it.severity] : ''} · {it.source.name}</small>
				</h2>
				{#if it.summary}<p>{it.summary}</p>{/if}
				<p class="refs">
					{it.cves.join(', ') || it.external_id}
					{#if it.cvss}· CVSS {it.cvss.score}{/if}
					{#if it.kev}· KEV{/if}
					{#if it.risks.length}· Risques liés : {it.risks.map((k) => k.code).join(', ')}{/if}
				</p>
			</article>
		{/each}
	{:else}
		{#each leaks as l (l.id)}
			<article>
				<h2>{l.organisation} <small>{LEAK_TYPE_LABEL[l.type]} · {l.country ?? ''}</small></h2>
				<p class="refs">
					{l.data_classes.join(', ') || 'Données non précisées'} · {count(l.records_count)} records · {l.source.name}
				</p>
			</article>
		{/each}
	{/if}
</section>

<style>
	.sheet h1 {
		font-size: 18px;
		margin: 0 0 4px;
	}
	.meta {
		font-size: 11px;
		color: #64748b;
		margin: 0 0 16px;
	}
	article {
		border-top: 1px solid #e2e8f0;
		padding: 8px 0;
		break-inside: avoid;
	}
	h2 {
		font-size: 13px;
		margin: 0 0 4px;
	}
	h2 small {
		font-weight: normal;
		color: #64748b;
		margin-left: 6px;
	}
	p {
		font-size: 11px;
		margin: 2px 0;
	}
	.refs {
		color: #475569;
	}
</style>
