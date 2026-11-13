<script lang="ts">
	import type { Leak } from '#lib/api.js';
	import { CONFIDENCE_LABEL, count, LEAK_TYPE_LABEL, safeUrl, SEVERITY_LABEL, shortDate } from '#lib/format.js';
	import type { Selection } from '#lib/selection.svelte.js';
	import { Expander } from '#lib/expand.svelte.js';

	let {
		items,
		selection,
		sectorName
	}: { items: Leak[]; selection: Selection<Leak>; sectorName: (code: string) => string } = $props();

	const expander = new Expander();
	const allSelected = $derived(items.length > 0 && items.every((l) => selection.has(String(l.id))));
	const regionNames = typeof Intl.DisplayNames === 'function' ? new Intl.DisplayNames(['fr'], { type: 'region' }) : null;

	function country(code: string | null): string {
		if (!code) return '-';
		try {
			return regionNames?.of(code) ?? code;
		} catch {
			return code;
		}
	}
</script>

<div class="table-wrapper">
	<table class="risk-table">
		<thead>
			<tr>
				<th class="col-check no-print">
					<input
						type="checkbox"
						aria-label="Tout sélectionner sur cette page"
						checked={allSelected}
						onchange={(e) => selection.setMany(items.map((l) => [String(l.id), l]), e.currentTarget.checked)}
					/>
				</th>
				<th class="col-date">Date</th>
				<th class="col-score">Type</th>
				<th class="col-main">Organisation</th>
				<th>Contexte</th>
				<th>Données exposées</th>
				<th class="col-ind">Source</th>
			</tr>
		</thead>
		<tbody>
			{#each items as l (l.id)}
				{@const url = safeUrl(l.url)}
				{@const open = expander.isOpen(String(l.id))}
				<!-- The whole row is a convenience target; the "Détails" button is the accessible control. -->
				<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
				<tr
					class="row-fold"
					class:unfolded={open}
					class:selected-row={selection.has(String(l.id))}
					onclick={(ev) => expander.onRowClick(ev, String(l.id))}
				>
					<td class="no-print">
						<input
							type="checkbox"
							aria-label="Sélectionner {l.organisation}"
							checked={selection.has(String(l.id))}
							onchange={(e) => selection.toggle(String(l.id), l, e.currentTarget.checked)}
						/>
					</td>
					<td class="col-date">{shortDate(l.disclosed_at ?? l.published_at)}</td>
					<td class="col-score">
						<span class="mini-badge leak-{l.type}">{LEAK_TYPE_LABEL[l.type]}</span>
						{#if l.severity}<div class="small leak-severity severity-{l.severity}" title="Gravité selon les données exposées">{SEVERITY_LABEL[l.severity]}</div>{/if}
					</td>
					<td>
						<span class="tag tag-leak">💧 Leak</span>
						<div class="item-source">📡 {l.source.name}</div>
						<div class="item-title">{l.organisation}</div>
						{#if l.confidence && l.confidence !== 'confirmed'}<div class="confidence confidence-{l.confidence}">⚠️ {CONFIDENCE_LABEL[l.confidence]}</div>{/if}
						{#if l.actor}<div class="item-text">Groupe revendiquant : <b>{l.actor}</b></div>{/if}
						{#if open && url}<div class="fold-details"><a class="link" href={url} target="_blank" rel="noopener noreferrer">🔗 Source</a></div>{/if}
						{#if open && l.rule_trace?.rules?.length}
							<details class="why fold-details">
								<summary title="Règles qui ont fixé la gravité">Pourquoi ?</summary>
								{#each l.rule_trace.rules as rule (rule)}<code class="rule">{rule}</code>{/each}
							</details>
						{/if}
						<button class="fold-toggle no-print" aria-expanded={open} onclick={() => expander.toggle(String(l.id))}>
							<span class="chevron">▸</span>
							{open ? 'Moins de détails' : 'Détails'}
						</button>
					</td>
					<td>
						<div class="small"><b>{country(l.country)}</b></div>
						{#if l.sector}<span class="sector-tag">{sectorName(l.sector)}</span>{/if}
					</td>
					<td class="small">
						{#if open}
							<div class="fold-details">
								{#each l.data_classes as d (d)}<div>{d}</div>{:else}<div class="muted unknown">type inconnu</div>{/each}
							</div>
						{:else if l.data_classes.length}
							<div>{l.data_classes[0]}</div>
							{#if l.data_classes.length > 1}<div class="more-hint">+ {l.data_classes.length - 1} autre{l.data_classes.length > 2 ? 's' : ''} type{l.data_classes.length > 2 ? 's' : ''}</div>{/if}
						{:else}
							<div class="muted unknown">type inconnu</div>
						{/if}
						<div class="records">
							{#if l.records_count !== null}<b>{count(l.records_count)}</b> <span class="muted">records</span>{:else}<span
									class="muted unknown">nombre inconnu</span
								>{/if}
						</div>
					</td>
					<td class="col-ind small">{l.source.name}</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>

<style>
	.records {
		margin-top: 4px;
	}
	.unknown {
		font-style: italic;
	}
	.leak-severity {
		margin-top: 4px;
		font-weight: 600;
	}
	.severity-critical {
		color: #b91c1c;
	}
	.severity-high {
		color: #ea580c;
	}
	.severity-medium {
		color: #ca8a04;
	}
	.severity-low {
		color: #16a34a;
	}
	.confidence {
		font-size: 11px;
		font-weight: 600;
		margin-top: 2px;
	}
	.confidence-claimed {
		color: #c2410c;
	}
	.confidence-untrusted {
		color: #b91c1c;
	}
	.why {
		margin-top: 6px;
		font-size: 11px;
	}
	.why summary {
		cursor: pointer;
		color: var(--muted);
	}
	.why summary:hover {
		color: var(--primary);
	}
	.rule {
		display: inline-block;
		font-size: 10px;
		background: #f1f5f9;
		color: var(--muted-strong);
		border-radius: 3px;
		padding: 1px 5px;
		margin: 3px 3px 0 0;
	}
</style>
