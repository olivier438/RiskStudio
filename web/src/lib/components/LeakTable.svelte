<script lang="ts">
	import type { Leak } from '#lib/api.js';
	import { count, LEAK_TYPE_LABEL, safeUrl, shortDate } from '#lib/format.js';
	import type { Selection } from '#lib/selection.svelte.js';

	let {
		items,
		selection,
		sectorName
	}: { items: Leak[]; selection: Selection<Leak>; sectorName: (code: string) => string } = $props();

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
				<tr class:selected-row={selection.has(String(l.id))}>
					<td class="no-print">
						<input
							type="checkbox"
							aria-label="Sélectionner {l.organisation}"
							checked={selection.has(String(l.id))}
							onchange={(e) => selection.toggle(String(l.id), l, e.currentTarget.checked)}
						/>
					</td>
					<td class="col-date">{shortDate(l.disclosed_at ?? l.published_at)}</td>
					<td class="col-score"><span class="mini-badge leak-{l.type}">{LEAK_TYPE_LABEL[l.type]}</span></td>
					<td>
						<span class="tag tag-leak">💧 Leak</span>
						<div class="item-source">📡 {l.source.name}</div>
						<div class="item-title">{l.organisation}</div>
						{#if l.actor}<div class="item-text">Groupe revendiquant : <b>{l.actor}</b></div>{/if}
						{#if url}<div><a class="link" href={url} target="_blank" rel="noopener noreferrer">🔗 Source</a></div>{/if}
					</td>
					<td>
						<div class="small"><b>{country(l.country)}</b></div>
						{#if l.sector}<span class="sector-tag">{sectorName(l.sector)}</span>{/if}
					</td>
					<td class="small">
						{#each l.data_classes as d (d)}<div>{d}</div>{:else}<div class="muted unknown">type inconnu</div>{/each}
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
</style>
