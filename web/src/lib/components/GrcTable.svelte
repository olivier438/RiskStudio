<script lang="ts">
	import type { Risk } from '#lib/api.js';
	import { impactClass, shortDate } from '#lib/format.js';
	import type { RiskEdits, Selection } from '#lib/selection.svelte.js';
	import type { SvelteMap } from 'svelte/reactivity';
	import CiaBadges from './CiaBadges.svelte';
	import EnvTag from './EnvTag.svelte';
	import Mappings from './Mappings.svelte';

	let {
		items,
		selection,
		sectorName,
		editMode = false,
		edits
	}: {
		items: Risk[];
		selection: Selection<Risk>;
		sectorName: (code: string) => string;
		editMode?: boolean;
		edits: SvelteMap<string, RiskEdits>;
	} = $props();

	const allSelected = $derived(items.length > 0 && items.every((r) => selection.has(r.code)));

	function edited(code: string, field: keyof RiskEdits, value: string): void {
		edits.set(code, { ...edits.get(code), [field]: value.trim() });
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
						onchange={(e) => selection.setMany(items.map((r) => [r.code, r]), e.currentTarget.checked)}
					/>
				</th>
				<th class="col-date">Date</th>
				<th class="col-score">Impact</th>
				<th class="col-main">Risque</th>
				<th>Contexte</th>
				<th>Référentiels</th>
				<th class="col-ind">CIA</th>
			</tr>
		</thead>
		<tbody>
			{#each items as r (r.code)}
				{@const e = edits.get(r.code)}
				<tr class:selected-row={selection.has(r.code)}>
					<td class="no-print">
						<input
							type="checkbox"
							aria-label="Sélectionner {r.code}"
							checked={selection.has(r.code)}
							onchange={(ev) => selection.toggle(r.code, r, ev.currentTarget.checked)}
						/>
					</td>
					<td class="col-date">{shortDate(r.published_at)}</td>
					<td class="col-score">
						<span class="score {impactClass(r.impact)}">{r.impact}</span><span class="score-max">/5</span>
					</td>
					<td>
						<EnvTag env={r.environment} />
						<span class="code">{r.code}</span>
						<div
							class="item-title editable"
							contenteditable={editMode}
							onblur={(ev) => edited(r.code, 'title', ev.currentTarget.innerText)}
						>
							{e?.title ?? r.title}
						</div>
						<div
							class="item-text editable"
							contenteditable={editMode}
							onblur={(ev) => edited(r.code, 'scenario', ev.currentTarget.innerText)}
						>
							{e?.scenario ?? r.scenario}
						</div>
						<div class="item-measures">
							✅ <span
								class="editable"
								contenteditable={editMode}
								onblur={(ev) => edited(r.code, 'measures', ev.currentTarget.innerText)}>{e?.measures ?? r.measures}</span
							>
						</div>
					</td>
					<td>
						{#each r.sectors as s (s)}<span class="sector-tag">{sectorName(s)}</span>{:else}<small class="muted"
								>Tous secteurs</small
							>{/each}
						<div class="category"><b>{r.category.name_fr}</b></div>
						<small class="threat">{r.threat}</small>
					</td>
					<td><Mappings controls={r.controls} /></td>
					<td class="col-ind"><CiaBadges cia={r.cia} /></td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>

<style>
	.code {
		font-size: 10px;
		color: #94a3b8;
		margin-left: 6px;
	}
	.category {
		margin-top: 4px;
		font-size: 11px;
	}
	.threat {
		color: var(--muted);
	}
</style>
