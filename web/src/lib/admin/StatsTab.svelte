<script lang="ts">
	import { ApiError } from '#lib/api.js';
	import { adminApi, type Statistics } from '#lib/admin-api.js';
	import { SEVERITY_LABEL } from '#lib/format.js';

	let stats = $state<Statistics | null>(null);
	let error = $state<string | null>(null);

	const STATUS: Record<string, string> = {
		published: 'Publiés',
		pending: 'En attente',
		rejected: 'Rejetés',
		archived: 'Archivés',
		draft: 'Brouillons',
		approved: 'Approuvées'
	};
	const sum = (o: Record<string, number>) => Object.values(o).reduce((a, b) => a + b, 0);
	const maxRuns = $derived(Math.max(1, ...(stats?.runs_7d.map((d) => Number(d.items_new)) ?? [1])));
	const maxLinked = $derived(Math.max(1, ...(stats?.top_linked_risks.map((r) => Number(r.items)) ?? [1])));

	$effect(() => {
		adminApi
			.statistics()
			.then((s) => (stats = s))
			.catch((e) => (error = e instanceof ApiError ? e.message : 'Erreur de chargement.'));
	});
</script>

{#if error}<div class="a-error" role="alert">{error}</div>{/if}

{#if stats}
	<div class="grid">
		{#each [{ title: 'Risques', data: stats.risks }, { title: 'Alertes cyber', data: stats.intel }, { title: 'Fuites', data: stats.leaks }, { title: 'Propositions', data: stats.proposals }] as block (block.title)}
			<div class="tile">
				<h3>{block.title}</h3>
				<p class="big">{sum(block.data)}</p>
				<ul>
					{#each Object.entries(block.data) as [status, n] (status)}<li>{STATUS[status] ?? status} : <b>{n}</b></li>{/each}
				</ul>
			</div>
		{/each}
	</div>

	<div class="grid two">
		<div class="tile">
			<h3>Alertes publiées par sévérité</h3>
			<ul>
				{#each Object.entries(stats.intel_by_severity) as [sev, n] (sev)}<li>{SEVERITY_LABEL[sev] ?? 'Inconnue'} : <b>{n}</b></li>{/each}
			</ul>
			<h3 class="spaced">Risques du catalogue publiés</h3>
			<ul>
				<li>Catalogue : <b>{stats.risks_by_origin.catalogue ?? 0}</b></li>
				<li>Communauté : <b>{stats.risks_by_origin.community ?? 0}</b></li>
			</ul>
		</div>
		<div class="tile">
			<h3>Collecteur, 7 derniers jours</h3>
			{#each stats.runs_7d as d (d.day)}
				<div class="bar-row">
					<span class="label">{new Date(d.day).toLocaleDateString('fr-BE', { weekday: 'short', day: '2-digit' })}</span>
					<meter min="0" max={maxRuns} value={Number(d.items_new)}></meter>
					<span class="value">{d.items_new} nouveaux · {d.runs} passages{Number(d.failed) ? ` · ${d.failed} échecs` : ''}</span>
				</div>
			{:else}
				<p class="a-muted">Aucun passage enregistré.</p>
			{/each}
		</div>
	</div>

	<div class="tile">
		<h3>Risques du catalogue les plus matérialisés par la veille</h3>
		{#each stats.top_linked_risks as r (r.code)}
			<div class="bar-row">
				<span class="label"><code>{r.code}</code></span>
				<meter min="0" max={maxLinked} value={Number(r.items)}></meter>
				<span class="value">{r.items} · {r.title}</span>
			</div>
		{:else}
			<p class="a-muted">Pas encore de lien entre la veille et le catalogue.</p>
		{/each}
	</div>
{:else if !error}
	<p class="a-muted">Chargement...</p>
{/if}

<style>
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 14px;
		margin-bottom: 14px;
	}
	.grid.two {
		grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
	}
	.tile {
		background: var(--a-surface);
		border: 1px solid var(--a-border);
		border-radius: 12px;
		padding: 16px 18px;
		margin-bottom: 14px;
	}
	h3 {
		margin: 0 0 8px;
		font-size: 12px;
		text-transform: uppercase;
		letter-spacing: 0.5px;
		color: var(--a-muted);
	}
	h3.spaced {
		margin-top: 16px;
	}
	.big {
		font-size: 28px;
		font-weight: bold;
		margin: 0 0 6px;
	}
	ul {
		margin: 0;
		padding-left: 16px;
		font-size: 13px;
		line-height: 1.7;
	}
	.bar-row {
		display: grid;
		grid-template-columns: 70px 1fr minmax(0, 2fr);
		gap: 10px;
		align-items: center;
		font-size: 12px;
		margin: 6px 0;
	}
	.value {
		color: var(--a-muted);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	meter {
		width: 100%;
		height: 10px;
		appearance: none;
		background: var(--a-surface2);
		border: none;
		border-radius: 5px;
	}
	meter::-webkit-meter-bar {
		background: var(--a-surface2);
		border: none;
		border-radius: 5px;
	}
	meter::-webkit-meter-optimum-value {
		background: var(--primary);
		border-radius: 5px;
	}
	meter::-moz-meter-bar {
		background: var(--primary);
		border-radius: 5px;
	}
</style>
