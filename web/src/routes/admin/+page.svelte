<script lang="ts">
	import { onMount } from 'svelte';
	import { api, ApiError, type Reference } from '#lib/api.js';
	import { adminApi, type Admin, type QueueCounts } from '#lib/admin-api.js';
	import AuditTab from '#lib/admin/AuditTab.svelte';
	import CraTab from '#lib/admin/CraTab.svelte';
	import LoginCard from '#lib/admin/LoginCard.svelte';
	import QueueTab from '#lib/admin/QueueTab.svelte';
	import RisksTab from '#lib/admin/RisksTab.svelte';
	import SourcesTab from '#lib/admin/SourcesTab.svelte';
	import StatsTab from '#lib/admin/StatsTab.svelte';

	type Tab = 'queue' | 'risks' | 'sources' | 'stats' | 'audit' | 'cra';
	const TABS: { id: Tab; label: string }[] = [
		{ id: 'queue', label: '📥 À valider' },
		{ id: 'risks', label: '📋 Risques' },
		{ id: 'sources', label: '📡 Sources' },
		{ id: 'stats', label: '📊 Statistiques' },
		{ id: 'audit', label: '🧾 Journal' },
		{ id: 'cra', label: '🔒 CRA / ENISA' }
	];

	let admin = $state<Admin | null>(null);
	let checking = $state(true);
	let tab = $state<Tab>('queue');
	let counts = $state<QueueCounts>({ intel: 0, leaks: 0, proposals: 0 });
	let reference = $state<Reference | null>(null);
	const pending = $derived(counts.intel + counts.leaks + counts.proposals);

	const sectorName = (code: string) => reference?.sectors.find((s) => s.code === code)?.name_fr ?? code;
	const categoryName = (code: string) => reference?.categories.find((c) => c.code === code)?.name_fr ?? code;

	onMount(async () => {
		reference = await api.reference().catch(() => null);
		try {
			const me = await adminApi.me();
			admin = me.admin;
			counts = me.queue;
		} catch (e) {
			if (!(e instanceof ApiError && e.status === 401)) console.warn(e);
		} finally {
			checking = false;
		}
	});

	async function logout(): Promise<void> {
		await adminApi.logout().catch(() => null);
		admin = null;
	}
</script>

<svelte:head>
	<title>NOROSHI | Administration</title>
	<meta name="robots" content="noindex, nofollow" />
</svelte:head>

<div class="admin">
	{#if checking}
		<p class="a-muted center">Chargement...</p>
	{:else if !admin}
		<LoginCard
			onlogin={async (a) => {
				admin = a;
				counts = (await adminApi.me()).queue;
			}}
		/>
	{:else}
		<header class="topbar">
			<div class="brand">🛡️ NOROSHI <span>Administration</span></div>
			<div class="user">
				<a href="/" target="_blank" rel="noopener">Voir le site ↗</a>
				<span>{admin.display_name}</span>
				<button onclick={logout}>Se déconnecter</button>
			</div>
		</header>
		<nav class="tabs" aria-label="Sections">
			{#each TABS as t (t.id)}
				<button class="tab" class:active={tab === t.id} aria-current={tab === t.id ? 'page' : undefined} onclick={() => (tab = t.id)}>
					{t.label}
					{#if t.id === 'queue' && pending > 0}<span class="badge">{pending}</span>{/if}
				</button>
			{/each}
		</nav>
		<main class="content">
			{#if tab === 'queue'}
				<QueueTab {categoryName} {sectorName} oncounts={(c) => (counts = c)} />
			{:else if tab === 'risks' && reference}
				<RisksTab {reference} />
			{:else if tab === 'sources'}
				<SourcesTab />
			{:else if tab === 'stats'}
				<StatsTab />
			{:else if tab === 'audit'}
				<AuditTab />
			{:else if tab === 'cra'}
				<CraTab />
			{/if}
		</main>
	{/if}
</div>

<style>
	/* Dark back office, as in v4. Scoped variables: the public site stays light. */
	.admin {
		--a-bg: #0f172a;
		--a-surface: #1e293b;
		--a-surface2: #263548;
		--a-border: #334155;
		--a-text: #e2e8f0;
		--a-muted: #94a3b8;
		--a-success: #10b981;
		--a-warning: #f59e0b;
		--a-error: #f87171;
		background: var(--a-bg);
		color: var(--a-text);
		min-height: 100vh;
		margin: -20px;
	}
	.center {
		text-align: center;
		padding-top: 30vh;
	}
	.topbar {
		background: var(--a-surface);
		border-bottom: 1px solid var(--a-border);
		padding: 14px 24px;
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 12px;
		flex-wrap: wrap;
	}
	.brand {
		font-weight: bold;
		color: var(--primary);
		font-size: 16px;
	}
	.brand span {
		color: var(--a-muted);
		font-weight: normal;
		margin-left: 6px;
	}
	.user {
		display: flex;
		gap: 14px;
		align-items: center;
		font-size: 13px;
	}
	.user a {
		color: var(--a-muted);
	}
	.user button {
		background: var(--a-surface2);
		border: 1px solid var(--a-border);
		color: var(--a-text);
		border-radius: 6px;
		padding: 6px 12px;
		cursor: pointer;
		font-family: inherit;
	}
	.tabs {
		display: flex;
		background: var(--a-surface);
		border-bottom: 1px solid var(--a-border);
		padding: 0 24px;
		overflow-x: auto;
	}
	.tab {
		padding: 14px 18px;
		cursor: pointer;
		font-size: 13px;
		font-weight: 600;
		color: var(--a-muted);
		border: none;
		border-bottom: 3px solid transparent;
		background: none;
		font-family: inherit;
		white-space: nowrap;
	}
	.tab:hover {
		color: var(--a-text);
	}
	.tab.active {
		color: var(--primary);
		border-bottom-color: var(--primary);
	}
	.badge {
		background: var(--a-warning);
		color: #1c1917;
		font-size: 10px;
		font-weight: bold;
		padding: 2px 6px;
		border-radius: 10px;
		margin-left: 6px;
	}
	.content {
		padding: 24px;
		max-width: 1300px;
		margin: 0 auto;
	}
	/* Shared by the tab components. */
	.admin :global(.a-muted) {
		color: var(--a-muted);
	}
	.admin :global(.a-error) {
		background: rgba(248, 113, 113, 0.1);
		border: 1px solid var(--a-error);
		color: var(--a-error);
		border-radius: 8px;
		padding: 10px 14px;
		margin-bottom: 14px;
		font-size: 13px;
	}
	.admin :global(.a-ok) {
		background: rgba(16, 185, 129, 0.1);
		border: 1px solid var(--a-success);
		color: var(--a-success);
		border-radius: 8px;
		padding: 10px 14px;
		margin-bottom: 14px;
		font-size: 13px;
	}
	.admin :global(.a-ok-inline) {
		color: var(--a-success);
		font-size: 12px;
	}
	.admin :global(.a-table) {
		width: 100%;
		border-collapse: collapse;
		background: var(--a-surface);
		border-radius: 12px;
		overflow: hidden;
		font-size: 13px;
	}
	.admin :global(.a-table th) {
		text-align: left;
		padding: 11px 14px;
		font-size: 11px;
		text-transform: uppercase;
		color: var(--a-muted);
		border-bottom: 1px solid var(--a-border);
		background: var(--a-surface2);
	}
	.admin :global(.a-table td) {
		padding: 11px 14px;
		border-bottom: 1px solid var(--a-border);
		vertical-align: top;
	}
	.admin :global(code) {
		font-size: 12px;
	}
	@media (max-width: 760px) {
		.content {
			padding: 14px;
		}
		.admin :global(.a-table) {
			display: block;
			overflow-x: auto;
		}
	}
</style>
