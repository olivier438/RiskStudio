<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Health, type Reference } from '#lib/api.js';

	type Mode = 'grc' | 'cyber' | 'leaks';

	const MODES: { id: Mode; label: string }[] = [
		{ id: 'grc', label: '🛡️ GRC' },
		{ id: 'cyber', label: '⚡ Cyberrisques' },
		{ id: 'leaks', label: '💧 Data Leaks' }
	];

	let mode = $state<Mode>('grc');
	let health = $state<Health | null>(null);
	let reference = $state<Reference | null>(null);
	let risksTotal = $state<number | null>(null);
	let error = $state<string | null>(null);

	const controlsTotal = $derived(
		reference?.frameworks.reduce((sum, f) => sum + f.controls_count, 0) ?? 0
	);

	onMount(async () => {
		try {
			const [h, ref, risks] = await Promise.all([
				api.health(),
				api.reference(),
				api.risks({ per_page: 1 })
			]);
			health = h;
			reference = ref;
			risksTotal = risks.meta.total;
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		}
	});
</script>

<svelte:head>
	<title>Risk Studio v5 | GRC & Threat Intelligence</title>
	<meta
		name="description"
		content="Catalogue de risques GRC et veille cyber déterministe, mappés sur ISO 27001, NIS2, DORA, CyFun et NIST CSF."
	/>
</svelte:head>

<header class="app-header">
	<div class="app-title">
		<img src="/rs.jpg" alt="Risk Studio" class="logo" width="72" height="72" />
		<div>
			<h1>🛡️ Risk Studio <span class="version">v5</span></h1>
			<div class="meta-info">
				Base :
				{#if health}
					<b>{health.database === 'ok' ? 'connectée' : 'indisponible'}</b>
					{#if health.database === 'ok'}<span class="live"><span class="live-dot"></span>LIVE</span>{/if}
					<br />API <b>{health.version}</b>
				{:else if error}
					<b>indisponible</b>
				{:else}
					<b>Chargement...</b>
				{/if}
			</div>
		</div>
	</div>

	<div class="actions">
		<div class="mode-toggle" role="tablist" aria-label="Vue">
			{#each MODES as m (m.id)}
				<button
					class="mode-btn"
					class:active-grc={mode === 'grc' && m.id === 'grc'}
					class:active-cyber={mode === 'cyber' && m.id === 'cyber'}
					class:active-leaks={mode === 'leaks' && m.id === 'leaks'}
					role="tab"
					aria-selected={mode === m.id}
					onclick={() => (mode = m.id)}>{m.label}</button
				>
			{/each}
		</div>
		<button class="btn btn-propo" disabled>➕ Proposer un risque</button>
		<button class="btn btn-pdf" disabled>📄 PDF</button>
		<button class="btn btn-excel" disabled>📊 Excel</button>
	</div>
</header>

{#if error}
	<div class="error-msg" role="alert">Impossible de joindre l'API : {error}</div>
{:else if !reference}
	<div class="loading"><span class="loading-spinner"></span> Connexion à la base de données...</div>
{:else}
	<section class="dashboard" aria-label="Indicateurs">
		<div class="stat-card"><h3>Risques GRC</h3><p>{risksTotal ?? '-'}</p></div>
		<div class="stat-card sectors"><h3>Secteurs</h3><p>{reference.sectors.length}</p></div>
		<div class="stat-card frameworks"><h3>Référentiels</h3><p>{reference.frameworks.length}</p></div>
		<div class="stat-card controls"><h3>Contrôles</h3><p>{controlsTotal}</p></div>
	</section>

	<section class="panel">
		<h2>Catalogue v5 en place</h2>
		<p>
			Catalogue GRC chargé. La vue {MODES.find((m) => m.id === mode)?.label} (phase 3) et le
			collecteur (phase 4) arrivent ensuite. Référentiels disponibles :
		</p>
		<ul class="fw-list">
			{#each reference.frameworks as f (f.code)}
				<li>
					<b>{f.short_name}</b>
					{f.version ?? ''}
					<span class="muted"
						>{f.controls_count} contrôles</span
					>
				</li>
			{/each}
		</ul>
	</section>
{/if}

<style>
	.app-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 16px;
		flex-wrap: wrap;
		margin-bottom: 25px;
		border-bottom: 2px solid var(--border);
		padding-bottom: 15px;
	}
	.app-title {
		display: flex;
		align-items: center;
		gap: 14px;
	}
	.logo {
		height: 72px;
		width: 72px;
		object-fit: contain;
		border-radius: 10px;
	}
	h1 {
		margin: 0;
		font-size: 24px;
		color: var(--primary);
		line-height: 1;
		display: flex;
		align-items: center;
		gap: 10px;
	}
	.meta-info {
		font-size: 11px;
		color: var(--muted);
		margin-top: 8px;
		line-height: 1.4;
	}
	.meta-info b {
		color: var(--muted-strong);
	}
	.live {
		margin-left: 6px;
		font-size: 10px;
		color: var(--ok);
	}
	.actions {
		display: flex;
		gap: 10px;
		flex-wrap: wrap;
		align-items: center;
	}
	.mode-toggle {
		display: flex;
		background: #f1f5f9;
		border-radius: 10px;
		padding: 4px;
		gap: 4px;
	}
	.mode-btn {
		padding: 8px 18px;
		border-radius: 7px;
		border: none;
		cursor: pointer;
		font-size: 13px;
		font-weight: 600;
		font-family: inherit;
		transition: all 0.2s;
		background: transparent;
		color: var(--muted);
	}
	.mode-btn.active-grc {
		background: var(--primary);
		color: white;
		box-shadow: 0 2px 6px rgba(37, 99, 235, 0.3);
	}
	.mode-btn.active-cyber {
		background: var(--cyber);
		color: white;
		box-shadow: 0 2px 6px rgba(220, 38, 38, 0.3);
	}
	.mode-btn.active-leaks {
		background: var(--leaks);
		color: white;
		box-shadow: 0 2px 6px rgba(124, 58, 237, 0.3);
	}
	.dashboard {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 15px;
		margin-bottom: 25px;
	}
	.stat-card {
		background: var(--surface);
		padding: 15px;
		border-radius: 10px;
		box-shadow: var(--shadow-sm);
		border-top: 4px solid var(--primary);
	}
	.stat-card.sectors {
		border-top-color: var(--ot-color);
	}
	.stat-card.frameworks {
		border-top-color: var(--leaks);
	}
	.stat-card.controls {
		border-top-color: var(--ok);
	}
	.stat-card h3 {
		margin: 0;
		font-size: 11px;
		color: var(--muted);
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}
	.stat-card p {
		margin: 8px 0 0;
		font-size: 22px;
		font-weight: bold;
	}
	.panel {
		background: var(--surface);
		padding: 20px;
		border-radius: 12px;
		box-shadow: var(--shadow-md);
		font-size: 13px;
	}
	.panel h2 {
		margin: 0 0 8px;
		font-size: 16px;
	}
	.fw-list {
		margin: 10px 0 0;
		padding-left: 18px;
		line-height: 1.8;
	}
	.muted {
		color: var(--muted);
		margin-left: 6px;
	}
	@media (max-width: 768px) {
		.dashboard {
			grid-template-columns: repeat(2, 1fr);
		}
	}
</style>
