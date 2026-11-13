<script lang="ts">
	import type { Risk } from '#lib/api.js';
	import { Expander } from '#lib/expand.svelte.js';
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

	const expander = new Expander();
	const allSelected = $derived(items.length > 0 && items.every((r) => selection.has(r.code)));
	// In edit mode every row stays unfolded: all texts must be reachable.
	const isOpen = (code: string) => editMode || expander.isOpen(code);

	function edited(code: string, field: keyof RiskEdits, value: string): void {
		edits.set(code, { ...edits.get(code), [field]: value.trim() });
	}

	/** Compact view of the mappings: editorial ISO references, and how many other frameworks follow. */
	function isoSummary(r: Risk): { iso: string; others: number } {
		const iso = r.controls.filter((c) => c.framework === 'ISO27001_2022' && c.source === 'editorial').map((c) => c.ref);
		const others = new Set(r.controls.filter((c) => c.framework !== 'ISO27001_2022').map((c) => c.framework)).size;
		return { iso: iso.join(', '), others };
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
				{@const open = isOpen(r.code)}
				{@const summary = isoSummary(r)}
				<!-- The whole row is a convenience target; the "Détails" button is the accessible control. -->
				<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
				<tr
					class="row-fold"
					class:unfolded={open}
					class:selected-row={selection.has(r.code)}
					onclick={(ev) => !editMode && expander.onRowClick(ev, r.code)}
				>
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
							class:clamp-2={!open}
							contenteditable={editMode}
							onblur={(ev) => edited(r.code, 'scenario', ev.currentTarget.innerText)}
						>
							{e?.scenario ?? r.scenario}
						</div>
						{#if open}
							<div class="fold-details">
								<div class="item-measures">
									✅ <span
										class="editable"
										contenteditable={editMode}
										onblur={(ev) => edited(r.code, 'measures', ev.currentTarget.innerText)}
										>{e?.measures ?? r.measures}</span
									>
								</div>
								<div class="threat-line"><b>Menace :</b> {r.threat}</div>
							</div>
						{/if}
						{#if !editMode}
							<button class="fold-toggle no-print" aria-expanded={open} onclick={() => expander.toggle(r.code)}>
								<span class="chevron">▸</span>
								{open ? 'Moins de détails' : 'Détails'}
							</button>
						{/if}
					</td>
					<td>
						{#each r.sectors as s (s)}<span class="sector-tag">{sectorName(s)}</span>{:else}<small class="muted"
								>Tous secteurs</small
							>{/each}
						<div class="category"><b>{r.category.name_fr}</b></div>
					</td>
					<td>
						{#if open}
							<div class="fold-details"><Mappings controls={r.controls} /></div>
						{:else}
							<div class="fw-compact">
								{#if summary.iso}<b>📋 ISO :</b> {summary.iso}{:else}<span class="muted">Pas de contrôle ISO</span>{/if}
							</div>
							{#if summary.others}<div class="more-hint">+ {summary.others} autre{summary.others > 1 ? 's' : ''} référentiel{summary.others > 1 ? 's' : ''}</div>{/if}
						{/if}
					</td>
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
	.threat-line {
		font-size: 11px;
		color: var(--muted);
		margin-top: 4px;
	}
	.fw-compact {
		font-size: 11px;
		line-height: 1.6;
	}
</style>
