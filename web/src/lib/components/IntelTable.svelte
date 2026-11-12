<script lang="ts">
	import type { IntelItem } from '#lib/api.js';
	import { cvssClass, INTEL_TYPE_LABEL, percent, safeUrl, SEVERITY_LABEL, shortDate } from '#lib/format.js';
	import type { Selection } from '#lib/selection.svelte.js';
	import EnvTag from './EnvTag.svelte';

	let {
		items,
		selection,
		categoryName,
		onrisk
	}: {
		items: IntelItem[];
		selection: Selection<IntelItem>;
		categoryName: (code: string) => string;
		/** Opens a linked catalogue risk in the GRC view. */
		onrisk: (code: string) => void;
	} = $props();

	const allSelected = $derived(items.length > 0 && items.every((i) => selection.has(String(i.id))));
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
				<th class="col-score">Score</th>
				<th class="col-main">Alerte</th>
				<th>Contexte</th>
				<th>Références</th>
				<th class="col-ind">Indicateurs</th>
			</tr>
		</thead>
		<tbody>
			{#each items as it (it.id)}
				{@const url = safeUrl(it.url)}
				<tr class:selected-row={selection.has(String(it.id))} class:row-critical={it.critical}>
					<td class="no-print">
						<input
							type="checkbox"
							aria-label="Sélectionner {it.external_id}"
							checked={selection.has(String(it.id))}
							onchange={(e) => selection.toggle(String(it.id), it, e.currentTarget.checked)}
						/>
					</td>
					<td class="col-date" title="Date de la source">{shortDate(it.source_published_at ?? it.published_at)}</td>
					<td class="col-score">
						{#if it.score !== null}
							<span class="score" class:impact-5={it.score >= 80} class:impact-4={it.score >= 60 && it.score < 80}
								>{it.score}</span
							><span class="score-max">/100</span>
						{:else}<span class="muted">-</span>{/if}
					</td>
					<td>
						<EnvTag env={it.environment} />
						<span class="kind">{INTEL_TYPE_LABEL[it.type] ?? it.type}</span>
						<div class="item-source">📡 {it.source.name}</div>
						<div class="item-title">{it.title}</div>
						{#if it.summary}<div class="item-text clamp" title={it.summary}>{it.summary}</div>{/if}
						{#if it.risks.length}
							<div class="linked">
								{#each it.risks as k (k.code)}
									<button class="risk-link no-print" onclick={() => onrisk(k.code)} title="Ouvrir dans le catalogue GRC"
										>↳ {k.code} {k.title}</button
									>
									<span class="print-only">↳ {k.code} {k.title}</span>
								{/each}
							</div>
						{/if}
						{#if it.rule_trace?.rules?.length}
							<details class="why">
								<summary title="Règles qui ont classé cette alerte">Pourquoi ?</summary>
								{#each it.rule_trace.rules as rule (rule)}<code class="rule">{rule}</code>{/each}
							</details>
						{/if}
					</td>
					<td>
						{#each it.categories as c (c)}<div class="small"><b>{categoryName(c)}</b></div>{/each}
						{#each it.products as p (p.vendor + p.product)}<div class="small product">{p.vendor} {p.product}</div>{/each}
						{#if !it.categories.length && !it.products.length}<span class="muted">-</span>{/if}
					</td>
					<td class="small">
						{#each it.cves as cve (cve)}<div class="cve">{cve}</div>{/each}
						{#if it.cvss}<span class="cvss-badge {cvssClass(it.cvss.score)}">CVSS {it.cvss.score.toFixed(1)}</span>{/if}
						{#if it.epss}<div class="muted" title="Probabilité d'exploitation à 30 jours (FIRST EPSS)">
								EPSS {percent(it.epss.score)}
							</div>{/if}
						{#if it.kev_due_date}<div class="due">Échéance KEV : {shortDate(it.kev_due_date)}</div>{/if}
						{#if url}<div><a class="link" href={url} target="_blank" rel="noopener noreferrer">🔗 Source</a></div>{/if}
					</td>
					<td class="col-ind">
						{#if it.critical}<div><span class="badge-critical">🔥 CRITIQUE</span></div>{/if}
						{#if it.kev}<div><span class="mini-badge badge-kev" title="Known Exploited Vulnerabilities">KEV</span></div>{/if}
						{#if it.severity && !it.critical}<div class="small severity-{it.severity}">{SEVERITY_LABEL[it.severity]}</div>{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>

<style>
	.clamp {
		display: -webkit-box;
		-webkit-line-clamp: 3;
		line-clamp: 3;
		-webkit-box-orient: vertical;
		overflow: hidden;
	}
	.kind {
		font-size: 10px;
		color: var(--muted);
		margin-left: 6px;
	}
	.linked {
		margin-top: 6px;
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
	.product {
		color: var(--muted);
	}
	.cve {
		font-weight: 600;
		font-size: 12px;
	}
	.due {
		color: #b91c1c;
		font-weight: 600;
		font-size: 11px;
	}
	.severity-high {
		color: #ea580c;
		font-weight: 600;
	}
	.severity-medium {
		color: #ca8a04;
		font-weight: 600;
	}
	.severity-low {
		color: #16a34a;
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
