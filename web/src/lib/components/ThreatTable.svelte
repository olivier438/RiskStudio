<script lang="ts">
	import type { IntelItem } from '#lib/api.js';
	import { INTEL_TYPE_LABEL, safeUrl, SEVERITY_LABEL, shortDate } from '#lib/format.js';
	import type { Selection } from '#lib/selection.svelte.js';
	import { Expander } from '#lib/expand.svelte.js';
	import EnvTag from './EnvTag.svelte';

	let {
		items,
		selection,
		categoryName,
		sectorName,
		onrisk
	}: {
		items: IntelItem[];
		selection: Selection<IntelItem>;
		categoryName: (code: string) => string;
		sectorName: (code: string) => string;
		/** Opens a linked catalogue risk in the GRC view. */
		onrisk: (code: string) => void;
	} = $props();

	const expander = new Expander();
	const allSelected = $derived(items.length > 0 && items.every((i) => selection.has(String(i.id))));
	const regionNames = typeof Intl.DisplayNames === 'function' ? new Intl.DisplayNames(['fr'], { type: 'region' }) : null;

	function country(code: string): string {
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
						onchange={(e) => selection.setMany(items.map((i) => [String(i.id), i]), e.currentTarget.checked)}
					/>
				</th>
				<th class="col-date">Date</th>
				<th class="col-score">Gravité</th>
				<th class="col-main">Menace</th>
				<th>Cible</th>
				<th>Risques du catalogue</th>
				<th class="col-ind">Source</th>
			</tr>
		</thead>
		<tbody>
			{#each items as it (it.id)}
				{@const url = safeUrl(it.url)}
				{@const open = expander.isOpen(String(it.id))}
				<!-- The whole row is a convenience target; the "Détails" button is the accessible control. -->
				<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
				<tr
					class="row-fold"
					class:unfolded={open}
					class:selected-row={selection.has(String(it.id))}
					class:row-critical={it.critical}
					onclick={(ev) => expander.onRowClick(ev, String(it.id))}
				>
					<td class="no-print">
						<input
							type="checkbox"
							aria-label="Sélectionner {it.title}"
							checked={selection.has(String(it.id))}
							onchange={(e) => selection.toggle(String(it.id), it, e.currentTarget.checked)}
						/>
					</td>
					<td class="col-date" title="Date de la source">{shortDate(it.source_published_at ?? it.published_at)}</td>
					<td class="col-score">
						<span class="mini-badge type-{it.type}">{INTEL_TYPE_LABEL[it.type] ?? it.type}</span>
						{#if it.critical}<div class="sev severity-critical">🔥 Critique</div>
						{:else if it.severity}<div class="sev severity-{it.severity}">{SEVERITY_LABEL[it.severity]}</div>{/if}
					</td>
					<td>
						<EnvTag env={it.environment} />
						<div class="item-source">📡 {it.source.name}</div>
						<div class="item-title">{it.title}</div>
						{#if it.summary}<div class="item-text" class:clamp-2={!open}>{it.summary}</div>{/if}
						{#if open && url}<div class="fold-details"><a class="link" href={url} target="_blank" rel="noopener noreferrer">🔗 Source</a></div>{/if}
						{#if open && it.rule_trace?.rules?.length}
							<details class="why fold-details">
								<summary title="Règles qui ont classé cette menace">Pourquoi ?</summary>
								{#each it.rule_trace.rules as rule (rule)}<code class="rule">{rule}</code>{/each}
							</details>
						{/if}
						<button class="fold-toggle no-print" aria-expanded={open} onclick={() => expander.toggle(String(it.id))}>
							<span class="chevron">▸</span>
							{open ? 'Moins de détails' : 'Détails'}
						</button>
					</td>
					<td>
						{#if it.countries.length}<div class="small"><b>{it.countries.map(country).join(', ')}</b></div>{/if}
						{#each it.sectors as s (s)}<span class="sector-tag">{sectorName(s)}</span>{/each}
						{#each it.categories as c (c)}<div class="small muted">{categoryName(c)}</div>{/each}
						{#if !it.countries.length && !it.sectors.length && !it.categories.length}<span class="muted">-</span>{/if}
					</td>
					<td>
						{#each it.risks as k (k.code)}
							<button class="risk-link no-print" onclick={() => onrisk(k.code)} title="Ouvrir dans le catalogue GRC"
								>↳ {k.code} {k.title}</button
							>
							<span class="print-only">↳ {k.code} {k.title}</span>
						{:else}<span class="muted">-</span>{/each}
					</td>
					<td class="col-ind small">{it.source.name}</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>

<style>
	.sev {
		margin-top: 4px;
		font-size: 12px;
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
	.type-incident {
		background: #fff7ed;
		color: #c2410c;
	}
	.type-campaign {
		background: #fef2f2;
		color: #b91c1c;
	}
	.risk-link {
		display: block;
		background: none;
		border: none;
		padding: 1px 0;
		font: inherit;
		font-size: 11px;
		color: var(--primary);
		cursor: pointer;
		text-align: left;
	}
	.risk-link:hover {
		text-decoration: underline;
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
