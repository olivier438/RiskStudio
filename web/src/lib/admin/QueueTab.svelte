<script lang="ts">
	import { ApiError } from '#lib/api.js';
	import { adminApi, type PendingIntel, type PendingLeak, type Proposal, type QueueCounts } from '#lib/admin-api.js';
	import { count, dateAndTime, LEAK_TYPE_LABEL, safeUrl, SEVERITY_LABEL } from '#lib/format.js';

	let {
		categoryName,
		sectorName,
		oncounts
	}: {
		categoryName: (code: string) => string;
		sectorName: (code: string) => string;
		oncounts: (counts: QueueCounts) => void;
	} = $props();

	let intel = $state<PendingIntel[]>([]);
	let leaks = $state<PendingLeak[]>([]);
	let proposals = $state<Proposal[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let notes = $state<Record<string, string>>({});
	let message = $state<string | null>(null);

	async function load(): Promise<void> {
		loading = true;
		try {
			const q = await adminApi.queue();
			intel = q.intel;
			leaks = q.leaks;
			proposals = q.proposals;
			oncounts(q.counts);
			error = null;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Erreur de chargement.';
		} finally {
			loading = false;
		}
	}

	async function decide(kind: 'intel' | 'leak' | 'proposal', id: number, decision: string): Promise<void> {
		const note = notes[`${kind}-${id}`] || undefined;
		try {
			if (kind === 'intel') {
				oncounts((await adminApi.decideIntel(id, decision as 'publish', note)).counts);
				intel = intel.filter((i) => i.id !== id);
			} else if (kind === 'leak') {
				oncounts((await adminApi.decideLeak(id, decision as 'publish', note)).counts);
				leaks = leaks.filter((l) => l.id !== id);
			} else {
				const r = await adminApi.decideProposal(id, decision as 'approve', note);
				oncounts(r.counts);
				proposals = proposals.filter((p) => p.id !== id);
				message = r.risk_code ? `Proposition approuvée : risque ${r.risk_code} publié.` : 'Décision enregistrée.';
			}
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Action impossible.';
		}
	}

	async function decideAll(kind: 'intel' | 'leak', decision: 'publish' | 'reject'): Promise<void> {
		const ids = (kind === 'intel' ? intel : leaks).map((x) => x.id);
		if (!confirm(`${decision === 'publish' ? 'Publier' : 'Rejeter'} les ${ids.length} éléments de cette liste ?`)) return;
		for (const id of ids) await decide(kind, id, decision);
	}

	const text = (v: unknown) => (typeof v === 'string' ? v : '');

	$effect(() => {
		load();
	});
</script>

{#if error}<div class="a-error" role="alert">{error}</div>{/if}
{#if message}<div class="a-ok" role="status">{message}</div>{/if}

{#if loading}
	<p class="a-muted">Chargement...</p>
{:else}
	<section>
		<h2>📝 Propositions de la communauté <span class="count">{proposals.length}</span></h2>
		{#each proposals as p (p.id)}
			<article class="card">
				<header>
					<span class="pill">{p.kind === 'risk' ? 'Nouveau risque' : 'Correction'}</span>
					<span class="a-muted">#{p.id} · {dateAndTime(p.created_at)} · {p.submitter_name ?? 'Anonyme'}{p.submitter_email ? ` <${p.submitter_email}>` : ''}</span>
				</header>
				{#if p.kind === 'risk'}
					<h3>{text(p.payload.title)}</h3>
					<p class="meta">
						{categoryName(text(p.payload.category))} · {text(p.payload.threat)} · Impact {String(p.payload.impact)}/5 · CIA {text(p.payload.cia)} · {text(p.payload.environment)}
						{#if Array.isArray(p.payload.sectors) && p.payload.sectors.length}· {p.payload.sectors.map((s) => sectorName(String(s))).join(', ')}{/if}
					</p>
					<p><b>Scénario :</b> {text(p.payload.scenario)}</p>
					<p><b>Mesures :</b> {text(p.payload.measures)}</p>
					{#if text(p.payload.references)}<p class="a-muted">Références suggérées : {text(p.payload.references)}</p>{/if}
				{:else}
					<h3>Correction de {text(p.payload.risk_code)}</h3>
					<p>{text(p.payload.message)}</p>
					<p class="a-muted">Une correction approuvée s'applique ensuite dans <code>db/catalogue/risks.csv</code>.</p>
				{/if}
				<footer>
					<input class="note" placeholder="Note (facultative, conservée au journal)" maxlength="1000" bind:value={notes[`proposal-${p.id}`]} />
					<button class="ok" onclick={() => decide('proposal', p.id, 'approve')}>✓ Approuver</button>
					<button class="ko" onclick={() => decide('proposal', p.id, 'reject')}>✕ Rejeter</button>
				</footer>
			</article>
		{:else}
			<p class="a-muted empty">Aucune proposition en attente.</p>
		{/each}
	</section>

	<section>
		<h2>
			⚡ Alertes cyber à valider <span class="count">{intel.length}</span>
			{#if intel.length > 1}
				<button class="small ok" onclick={() => decideAll('intel', 'publish')}>Tout publier</button>
				<button class="small ko" onclick={() => decideAll('intel', 'reject')}>Tout rejeter</button>
			{/if}
		</h2>
		{#each intel as i (i.id)}
			{@const url = safeUrl(i.url)}
			<article class="card">
				<header>
					<span class="pill">{i.source}</span>
					<span class="a-muted">{i.external_id} · {dateAndTime(i.source_published_at ?? i.created_at)}</span>
					{#if i.score !== null}<span class="score">{i.score}/100</span>{/if}
				</header>
				<h3>{i.title}</h3>
				{#if i.summary}<p class="clamp">{i.summary}</p>{/if}
				<p class="meta">
					{i.severity ? SEVERITY_LABEL[i.severity] : 'Sévérité inconnue'} · {i.environment}
					{#if i.cvss !== null}· CVSS {i.cvss}{/if}
					{#if i.kev}· KEV{/if}
					{#if url}· <a href={url} target="_blank" rel="noopener noreferrer">Source ↗</a>{/if}
				</p>
				{#if i.rules.length}<p class="rules">{#each i.rules as r (r)}<code>{r}</code>{/each}</p>{/if}
				<footer>
					<input class="note" placeholder="Note (facultative)" maxlength="1000" bind:value={notes[`intel-${i.id}`]} />
					<button class="ok" onclick={() => decide('intel', i.id, 'publish')}>✓ Publier</button>
					<button class="ko" onclick={() => decide('intel', i.id, 'reject')}>✕ Rejeter</button>
				</footer>
			</article>
		{:else}
			<p class="a-muted empty">Aucune alerte en attente.</p>
		{/each}
	</section>

	<section>
		<h2>
			💧 Fuites à valider <span class="count">{leaks.length}</span>
			{#if leaks.length > 1}
				<button class="small ok" onclick={() => decideAll('leak', 'publish')}>Tout publier</button>
				<button class="small ko" onclick={() => decideAll('leak', 'reject')}>Tout rejeter</button>
			{/if}
		</h2>
		{#each leaks as l (l.id)}
			{@const url = safeUrl(l.url)}
			<article class="card">
				<header>
					<span class="pill">{l.source}</span>
					<span class="a-muted">{LEAK_TYPE_LABEL[l.type]} · {dateAndTime(l.disclosed_at ?? l.created_at)}</span>
				</header>
				<h3>{l.organisation}</h3>
				<p class="meta">
					{l.country ?? 'Pays inconnu'}{#if l.sector}· {sectorName(l.sector)}{/if}
					{#if l.actor}· Revendiqué par {l.actor}{/if}
					{#if l.records_count !== null}· {count(l.records_count)} records{/if}
					{#if url}· <a href={url} target="_blank" rel="noopener noreferrer">Source ↗</a>{/if}
				</p>
				{#if l.data_classes.length}<p class="a-muted">{l.data_classes.join(', ')}</p>{/if}
				<footer>
					<input class="note" placeholder="Note (facultative)" maxlength="1000" bind:value={notes[`leak-${l.id}`]} />
					<button class="ok" onclick={() => decide('leak', l.id, 'publish')}>✓ Publier</button>
					<button class="ko" onclick={() => decide('leak', l.id, 'reject')}>✕ Rejeter</button>
				</footer>
			</article>
		{:else}
			<p class="a-muted empty">Aucune fuite en attente.</p>
		{/each}
	</section>
{/if}

<style>
	section {
		margin-bottom: 32px;
	}
	h2 {
		font-size: 15px;
		margin: 0 0 12px;
		display: flex;
		gap: 10px;
		align-items: center;
		flex-wrap: wrap;
	}
	.count {
		background: var(--a-warning);
		color: #1c1917;
		font-size: 11px;
		padding: 2px 8px;
		border-radius: 10px;
	}
	.card {
		background: var(--a-surface);
		border: 1px solid var(--a-border);
		border-radius: 12px;
		padding: 16px 18px;
		margin-bottom: 12px;
	}
	.card header {
		display: flex;
		gap: 10px;
		align-items: center;
		font-size: 12px;
		flex-wrap: wrap;
	}
	.pill {
		background: var(--a-surface2);
		border: 1px solid var(--a-border);
		border-radius: 10px;
		padding: 2px 8px;
		font-size: 11px;
		font-weight: 600;
	}
	.score {
		margin-left: auto;
		font-weight: bold;
		color: var(--a-warning);
	}
	h3 {
		font-size: 14px;
		margin: 10px 0 6px;
	}
	p {
		font-size: 13px;
		margin: 4px 0;
		line-height: 1.5;
	}
	.meta {
		color: var(--a-muted);
		font-size: 12px;
	}
	.meta a {
		color: var(--primary);
	}
	.clamp {
		display: -webkit-box;
		-webkit-line-clamp: 3;
		line-clamp: 3;
		-webkit-box-orient: vertical;
		overflow: hidden;
	}
	.rules code {
		display: inline-block;
		font-size: 10px;
		background: var(--a-surface2);
		border-radius: 3px;
		padding: 1px 5px;
		margin: 2px 3px 0 0;
	}
	footer {
		display: flex;
		gap: 8px;
		margin-top: 12px;
		flex-wrap: wrap;
	}
	.note {
		flex: 1;
		min-width: 180px;
		padding: 8px 10px;
		background: var(--a-surface2);
		border: 1px solid var(--a-border);
		border-radius: 6px;
		color: var(--a-text);
		font-family: inherit;
		font-size: 12px;
	}
	button {
		border: none;
		border-radius: 6px;
		padding: 8px 14px;
		font-weight: bold;
		font-size: 12px;
		cursor: pointer;
		font-family: inherit;
	}
	button.small {
		padding: 4px 10px;
		font-size: 11px;
	}
	.ok {
		background: var(--a-success);
		color: white;
	}
	.ko {
		background: var(--a-surface2);
		color: var(--a-error);
		border: 1px solid var(--a-border);
	}
	.empty {
		font-size: 13px;
		font-style: italic;
	}
</style>
