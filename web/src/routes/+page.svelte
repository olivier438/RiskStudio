<script lang="ts">
	import { onMount } from 'svelte';
	import { SvelteMap } from 'svelte/reactivity';
	import { replaceState } from '$app/navigation';
	import { api, ApiError, type IntelItem, type Leak, type Page, type Reference, type Risk, type Stats } from '#lib/api.js';
	import AboutModal from '#lib/components/AboutModal.svelte';
	import Banner from '#lib/components/Banner.svelte';
	import ChangelogModal from '#lib/components/ChangelogModal.svelte';
	import GrcTable from '#lib/components/GrcTable.svelte';
	import IntelTable from '#lib/components/IntelTable.svelte';
	import LeakTable from '#lib/components/LeakTable.svelte';
	import Pagination from '#lib/components/Pagination.svelte';
	import PrintSheet from '#lib/components/PrintSheet.svelte';
	import Toolbar from '#lib/components/Toolbar.svelte';
	import { download, exportName, toCsv } from '#lib/export.js';
	import {
		cyberQuery,
		emptyCyber,
		emptyGrc,
		emptyLeaks,
		fromUrl,
		grcQuery,
		leakQuery,
		toSearch,
		type Mode,
		type ViewState
	} from '#lib/filters.js';
	import { count, dateAndTime, LEAK_TYPE_LABEL } from '#lib/format.js';
	import { notify, requestNotifications, toasts } from '#lib/notify.svelte.js';
	import { Selection, type RiskEdits } from '#lib/selection.svelte.js';

	const PER_PAGE = 50;
	const POLL_MS = 60_000;

	const MODES: { id: Mode; label: string; title: string }[] = [
		{ id: 'grc', label: '🛡️ GRC', title: 'Catalogue GRC' },
		{ id: 'cyber', label: '⚡ Cyberrisques', title: 'Cyberrisques' },
		{ id: 'leaks', label: '💧 Data Leaks', title: 'Data Leaks' }
	];

	let view = $state<ViewState>({ mode: 'grc', page: 1, grc: emptyGrc(), cyber: emptyCyber(), leaks: emptyLeaks() });
	let reference = $state<Reference | null>(null);
	let stats = $state<Stats | null>(null);
	let risks = $state<Page<Risk> | null>(null);
	let intel = $state<Page<IntelItem> | null>(null);
	let leaks = $state<Page<Leak> | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let live = $state(false);
	let editMode = $state(false);
	let aboutOpen = $state(false);
	let changelogOpen = $state(false);

	const grcSelection = new Selection<Risk>();
	const intelSelection = new Selection<IntelItem>();
	const leakSelection = new Selection<Leak>();
	const edits = new SvelteMap<string, RiskEdits>();

	const selectedCount = $derived(
		view.mode === 'grc' ? grcSelection.size : view.mode === 'cyber' ? intelSelection.size : leakSelection.size
	);
	const current = $derived(view.mode === 'grc' ? risks : view.mode === 'cyber' ? intel : leaks);
	const modeTitle = $derived(MODES.find((m) => m.id === view.mode)?.title ?? '');

	const sectorName = (code: string) => reference?.sectors.find((s) => s.code === code)?.name_fr ?? code;
	const categoryName = (code: string) => reference?.categories.find((c) => c.code === code)?.name_fr ?? code;

	// ---------------------------------------------------------------- loading
	let controller: AbortController | undefined;
	let debounceTimer: ReturnType<typeof setTimeout> | undefined;

	async function load(): Promise<void> {
		controller?.abort();
		const ctrl = new AbortController();
		controller = ctrl;
		const f: typeof fetch = (input, init) => fetch(input, { ...init, signal: ctrl.signal });
		loading = true;
		try {
			if (view.mode === 'grc') risks = await api.risks(grcQuery(view.grc, view.page, PER_PAGE), f);
			else if (view.mode === 'cyber') intel = await api.intel(cyberQuery(view.cyber, view.page, PER_PAGE), f);
			else leaks = await api.leaks(leakQuery(view.leaks, view.page, PER_PAGE), f);
			error = null;
		} catch (e) {
			if (e instanceof DOMException && e.name === 'AbortError') return;
			error = e instanceof ApiError ? e.message : 'Impossible de joindre l’API.';
		} finally {
			if (controller === ctrl) loading = false;
		}
	}

	function syncUrl(): void {
		const url = new URL(window.location.href);
		replaceState(url.pathname + toSearch(view, url.searchParams), {});
	}

	function filtersChanged(debounce: boolean): void {
		view.page = 1;
		syncUrl();
		clearTimeout(debounceTimer);
		if (debounce) debounceTimer = setTimeout(load, 250);
		else load();
	}

	function resetFilters(): void {
		if (view.mode === 'grc') view.grc = emptyGrc();
		else if (view.mode === 'cyber') view.cyber = emptyCyber();
		else view.leaks = emptyLeaks();
		filtersChanged(false);
	}

	function goToPage(p: number): void {
		view.page = p;
		syncUrl();
		load();
		document.getElementById('results')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
	}

	function switchMode(mode: Mode): void {
		if (mode === view.mode) return;
		view.mode = mode;
		view.page = 1;
		syncUrl();
		// Clicking is a user gesture: the only moment browsers allow asking.
		if (mode === 'cyber') requestNotifications();
		load();
	}

	function openRisk(code: string): void {
		view.grc = { ...emptyGrc(), q: code };
		view.mode = 'grc';
		view.page = 1;
		syncUrl();
		load();
	}

	// ---------------------------------------------------------------- polling
	let lastIntelId: number | null = null;
	let lastIntelAt: string | null = null;
	let lastLeakId: number | null = null;

	async function poll(initial = false): Promise<void> {
		if (!initial && document.visibilityState !== 'visible') return;
		try {
			const s = await api.stats();
			live = true;
			stats = s;
			if (initial) {
				lastIntelId = s.intel.latest_id;
				lastIntelAt = s.intel.latest_published_at;
				lastLeakId = s.leaks.latest_id;
				return;
			}
			if (s.intel.latest_id !== null && s.intel.latest_id !== lastIntelId) {
				const fresh = await api.intel({ since: lastIntelAt ?? undefined, per_page: 20 });
				lastIntelId = s.intel.latest_id;
				lastIntelAt = s.intel.latest_published_at;
				announce(fresh.data);
				if (view.mode === 'cyber' && view.page === 1) load();
			}
			if (s.leaks.latest_id !== null && s.leaks.latest_id !== lastLeakId) {
				lastLeakId = s.leaks.latest_id;
				toasts.show('💧 Nouvelle fuite de données publiée', 'info');
				if (view.mode === 'leaks' && view.page === 1) load();
			}
		} catch {
			live = false;
		}
	}

	function announce(items: IntelItem[]): void {
		if (!items.length) return;
		const critical = items.filter((i) => i.critical);
		if (critical.length) {
			toasts.show(
				critical.length === 1
					? `🔥 Alerte CRITIQUE : ${critical[0].title}`
					: `🔥 ${critical.length} nouvelles alertes CRITIQUES`,
				'critical'
			);
			for (const c of critical.slice(0, 3)) notify('NOROSHI : alerte critique', c.title);
		} else {
			toasts.show(
				items.length === 1 ? `⚡ Nouvelle alerte cyber : ${items[0].title}` : `⚡ ${items.length} nouvelles alertes cyber`,
				'new'
			);
		}
	}

	onMount(() => {
		const url = new URL(window.location.href);
		view = fromUrl(url);
		editMode = url.searchParams.has('edit');

		api
			.reference()
			.then((r) => (reference = r))
			.catch(() => (error = 'Impossible de joindre l’API.'));
		load();
		poll(true);
		const timer = setInterval(() => poll(), POLL_MS);
		const onVisible = () => document.visibilityState === 'visible' && poll();
		document.addEventListener('visibilitychange', onVisible);
		return () => {
			clearInterval(timer);
			document.removeEventListener('visibilitychange', onVisible);
		};
	});

	// ---------------------------------------------------------------- export
	function exportCsv(): void {
		if (view.mode === 'grc') {
			const refs = (r: Risk, fw: string) =>
				r.controls
					.filter((c) => c.framework === fw)
					.map((c) => c.ref)
					.join(', ');
			download(
				exportName('risques'),
				toCsv(
					['Code', 'Titre', 'Catégorie', 'Secteurs', 'Menace', 'C', 'I', 'A', 'Environnement', 'Impact', 'Scénario', 'Mesures', 'ISO 27001', 'NIS2', 'DORA', 'CRA', 'CyFun 2023', 'NIST CSF 2.0'],
					grcSelection.values().map((r) => {
						const e = edits.get(r.code);
						return [
							r.code, e?.title ?? r.title, r.category.name_fr, r.sectors.map(sectorName).join(' | ') || 'Tous', r.threat,
							r.cia.confidentiality, r.cia.integrity, r.cia.availability, r.environment, r.impact,
							e?.scenario ?? r.scenario, e?.measures ?? r.measures,
							refs(r, 'ISO27001_2022'), refs(r, 'NIS2'), refs(r, 'DORA'), refs(r, 'CRA'), refs(r, 'CYFUN_2023'), refs(r, 'NIST_CSF_2')
						];
					})
				)
			);
		} else if (view.mode === 'cyber') {
			download(
				exportName('veille'),
				toCsv(
					['Identifiant', 'Publication', 'Titre', 'Source', 'Type', 'Critique', 'Sévérité', 'Score', 'CVE', 'CVSS', 'EPSS', 'KEV', 'Échéance KEV', 'Produits', 'Catégories', 'Risques liés', 'URL', 'Règles appliquées'],
					intelSelection.values().map((i) => [
						i.external_id, i.source_published_at ?? i.published_at, i.title, i.source.name, i.type, i.critical, i.severity, i.score,
						i.cves.join(', '), i.cvss?.score, i.epss?.score, i.kev, i.kev_due_date,
						i.products.map((p) => `${p.vendor} ${p.product}`).join(', '), i.categories.map(categoryName).join(', '),
						i.risks.map((k) => k.code).join(', '), i.url, i.rule_trace?.rules?.join(' | ')
					])
				)
			);
		} else {
			download(
				exportName('fuites'),
				toCsv(
					['Date', 'Organisation', 'Type', 'Pays', 'Secteur', 'Groupe', 'Records', 'Données exposées', 'Source', 'URL'],
					leakSelection.values().map((l) => [
						l.disclosed_at ?? l.published_at, l.organisation, LEAK_TYPE_LABEL[l.type], l.country,
						l.sector ? sectorName(l.sector) : '', l.actor, l.records_count, l.data_classes.join(', '), l.source.name, l.url
					])
				)
			);
		}
	}
</script>

<svelte:head>
	<title>NOROSHI | {view.mode === 'grc' ? 'Catalogue GRC' : view.mode === 'cyber' ? 'Cyberrisques' : 'Data Leaks'}</title>
	<meta
		name="description"
		content="Catalogue de risques GRC et veille cyber sans IA, mappés sur ISO 27001, NIS2, DORA, CRA, CyFun et NIST CSF."
	/>
</svelte:head>

{#if toasts.current}
	<button class="toast-alert toast-{toasts.current.kind} no-print" onclick={() => toasts.dismiss()} aria-live="polite"
		>{toasts.current.message}</button
	>
{/if}

<div class="app mode-{view.mode}">
	<Banner mode={view.mode} />
	<header class="app-header no-print">
		<div class="app-title">
			<img src="/logo.jpg" alt="NOROSHI" class="logo" width="72" height="72" />
			<div>
				<h2 class="view-title">
					{modeTitle}
					{#if stats && stats.intel.critical_recent > 0}
						<button
							class="critical-badge"
							onclick={() => switchMode('cyber')}
							title="Alertes critiques publiées ces {stats.intel.critical_window_days} derniers jours"
						>
							🔥 <b>{stats.intel.critical_recent}</b> critique{stats.intel.critical_recent > 1 ? 's' : ''}
						</button>
					{/if}
				</h2>
				<div class="meta-info">
					Base : <b>{stats ? dateAndTime(stats.last_update) : 'Chargement...'}</b>
					{#if live}<span class="live"><span class="live-dot"></span>LIVE</span>{/if}<br />
					<button class="about-link" onclick={() => (aboutOpen = true)}>ℹ️ À propos de NOROSHI</button>
					·
					<button class="about-link" onclick={() => (changelogOpen = true)}>📋 Changelog</button>
				</div>
			</div>
		</div>

		<div class="actions">
			<div class="mode-toggle" role="tablist" aria-label="Vue">
				{#each MODES as m (m.id)}
					<button
						class="mode-btn"
						class:active-grc={view.mode === 'grc' && m.id === 'grc'}
						class:active-cyber={view.mode === 'cyber' && m.id === 'cyber'}
						class:active-leaks={view.mode === 'leaks' && m.id === 'leaks'}
						role="tab"
						aria-selected={view.mode === m.id}
						onclick={() => switchMode(m.id)}>{m.label}</button
					>
				{/each}
			</div>
			<a class="btn btn-propo" href="/proposer/">➕ Proposer un risque</a>
			<button class="btn btn-pdf" disabled={selectedCount === 0} onclick={() => window.print()}>📄 PDF</button>
			<button class="btn btn-excel" disabled={selectedCount === 0} onclick={exportCsv}
				>📊 Excel{selectedCount ? ` (${selectedCount})` : ''}</button
			>
		</div>
	</header>

	<section class="dashboard no-print" aria-label="Indicateurs">
		<div class="stat-card total">
			<h3>Total</h3>
			<p>{stats ? count(stats.risks.total + stats.intel.total + stats.leaks.total) : '-'}</p>
		</div>
		<div class="stat-card grc"><h3>GRC</h3><p>{count(stats?.risks.total)}</p></div>
		<div class="stat-card cyber"><h3>Cyber</h3><p>{count(stats?.intel.total)}</p></div>
		<div class="stat-card leaks"><h3>Data Leaks</h3><p>{count(stats?.leaks.total)}</p></div>
		<div class="stat-card updated"><h3>Dernier update</h3><p class="date">{dateAndTime(stats?.last_update)}</p></div>
	</section>

	{#if editMode && view.mode === 'grc'}
		<div class="edit-banner no-print">
			✏️ Mode édition : cliquez sur un titre, un scénario ou des mesures pour l'adapter à votre mission. Les
			modifications restent dans votre navigateur et sont reprises dans l'export, rien n'est enregistré.
		</div>
	{/if}

	{#if reference}
		<Toolbar
			mode={view.mode}
			{reference}
			bind:grc={view.grc}
			bind:cyber={view.cyber}
			bind:leaks={view.leaks}
			onchange={filtersChanged}
			onreset={resetFilters}
		/>
	{/if}

	<div id="results" class="no-print">
		{#if error}
			<div class="error-msg" role="alert">❌ <b>Impossible de charger les données :</b> {error}</div>
		{:else if !current}
			<div class="loading"><span class="loading-spinner"></span> Connexion à la base de données...</div>
		{:else if current.data.length === 0}
			<div class="no-results">
				{#if view.mode === 'grc'}🔍 Aucun risque ne correspond à vos critères.
				{:else if view.mode === 'cyber'}🔍 Aucune alerte ne correspond à vos critères.
				{:else}🔍 Aucune fuite ne correspond à vos critères.{/if}
			</div>
		{:else}
			<div class:stale={loading}>
				{#if view.mode === 'grc' && risks}
					<GrcTable items={risks.data} selection={grcSelection} {sectorName} {editMode} {edits} />
				{:else if view.mode === 'cyber' && intel}
					<IntelTable items={intel.data} selection={intelSelection} {categoryName} onrisk={openRisk} />
				{:else if view.mode === 'leaks' && leaks}
					<LeakTable items={leaks.data} selection={leakSelection} {sectorName} />
				{/if}
			</div>
			<Pagination
				page={current.meta.page}
				pages={current.meta.pages}
				total={current.meta.total}
				perPage={current.meta.per_page}
				onpage={goToPage}
			/>
		{/if}
	</div>

	<PrintSheet
		mode={view.mode}
		risks={grcSelection.values()}
		intel={intelSelection.values()}
		leaks={leakSelection.values()}
		{edits}
	/>
</div>

<AboutModal bind:open={aboutOpen} />
<ChangelogModal bind:open={changelogOpen} />

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
	.view-title {
		margin: 0;
		font-size: 24px;
		color: var(--primary);
		line-height: 1;
		display: flex;
		align-items: center;
		gap: 10px;
		flex-wrap: wrap;
	}
	.mode-cyber .view-title {
		color: var(--cyber);
	}
	.mode-leaks .view-title {
		color: var(--leaks);
	}
	.critical-badge {
		font-size: 11px;
		font-weight: 600;
		color: #dc2626;
		background: #fff1f1;
		border: 1px solid rgba(220, 38, 38, 0.3);
		border-radius: 20px;
		padding: 3px 10px;
		white-space: nowrap;
		cursor: pointer;
		font-family: inherit;
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
	.about-link {
		font-size: 11px;
		color: #94a3b8;
		cursor: pointer;
		text-decoration: underline;
		margin-top: 4px;
		display: inline-block;
		background: none;
		border: none;
		padding: 0;
		font-family: inherit;
	}
	.about-link:hover {
		color: var(--primary);
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
		grid-template-columns: repeat(5, 1fr);
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
	.stat-card.cyber {
		border-top-color: var(--ot-color);
	}
	.stat-card.leaks {
		border-top-color: var(--leaks);
	}
	.stat-card.updated {
		border-top-color: var(--ok);
	}
	.mode-cyber .stat-card {
		border-top-color: var(--cyber);
	}
	.mode-leaks .stat-card {
		border-top-color: var(--leaks);
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
	.stat-card p.date {
		font-size: 13px;
	}
	.edit-banner {
		background: #fffbeb;
		border: 1px solid #fcd34d;
		color: #92400e;
		border-radius: 8px;
		padding: 10px 14px;
		font-size: 12px;
		margin-bottom: 16px;
	}
	.stale {
		opacity: 0.6;
		transition: opacity 0.2s;
	}
	@media (max-width: 900px) {
		.dashboard {
			grid-template-columns: repeat(2, 1fr);
		}
		.stat-card.updated {
			grid-column: span 2;
		}
	}
</style>
