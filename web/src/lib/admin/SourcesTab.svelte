<script lang="ts">
	import { ApiError } from '#lib/api.js';
	import { adminApi, type AdminSource, type ProbeReport } from '#lib/admin-api.js';
	import { dateAndTime } from '#lib/format.js';

	let sources = $state<AdminSource[]>([]);
	let error = $state<string | null>(null);
	let reports = $state<Record<string, ProbeReport>>({});
	let probing = $state<Record<string, boolean>>({});
	let probingAll = $state(false);
	let testUrl = $state('');
	let urlReport = $state<ProbeReport | null>(null);
	let urlBusy = $state(false);

	const VERDICT: Record<string, { icon: string; cls: string }> = {
		works: { icon: '✅', cls: 'good' },
		reachable: { icon: '✅', cls: 'good' },
		redirect: { icon: '↪️', cls: 'warn' },
		format: { icon: '⚠️', cls: 'warn' },
		no_parser: { icon: 'ℹ️', cls: 'off' },
		blocked: { icon: '⛔', cls: 'bad' },
		unreachable: { icon: '⛔', cls: 'bad' },
		error: { icon: '⛔', cls: 'bad' },
		refused: { icon: '🚫', cls: 'bad' }
	};

	async function probe(code: string): Promise<void> {
		probing[code] = true;
		try {
			reports[code] = (await adminApi.probeSource(code)).data;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Test impossible.';
		} finally {
			probing[code] = false;
		}
	}

	// One source after the other: each test may take up to 15 seconds on shared hosting.
	async function probeAll(): Promise<void> {
		probingAll = true;
		for (const s of sources) await probe(s.code);
		probingAll = false;
	}

	async function probeUrl(ev: SubmitEvent): Promise<void> {
		ev.preventDefault();
		urlBusy = true;
		urlReport = null;
		try {
			urlReport = (await adminApi.probeUrl(testUrl.trim())).data;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Test impossible.';
		} finally {
			urlBusy = false;
		}
	}

	function size(bytes: number): string {
		return bytes >= 1024 ? `${Math.round(bytes / 1024)} Ko` : `${bytes} o`;
	}

	async function load(): Promise<void> {
		try {
			sources = (await adminApi.sources()).data;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Erreur de chargement.';
		}
	}

	async function toggle(s: AdminSource, field: 'enabled' | 'authoritative'): Promise<void> {
		const value = !s[field];
		const what =
			field === 'enabled'
				? value
					? `Activer ${s.name} ?`
					: `Désactiver ${s.name} ? Le collecteur ne l'interrogera plus.`
				: value
					? `Publier directement ce que rapporte ${s.name}, sans validation ?`
					: `Soumettre désormais ${s.name} à validation éditoriale ?`;
		if (!confirm(what)) return;
		try {
			sources = (await adminApi.updateSource(s.code, { [field]: value })).data;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Action impossible.';
		}
	}

	function health(s: AdminSource): { label: string; cls: string } {
		if (!s.enabled) return { label: 'Désactivée', cls: 'off' };
		if (!s.last_run_at) return { label: 'Jamais lancée', cls: 'warn' };
		if (s.last_status === 'failed') return { label: 'En échec', cls: 'bad' };
		const late = s.last_success_at && Date.now() - new Date(s.last_success_at).getTime() > 3 * s.poll_minutes * 60_000;
		if (late) return { label: 'En retard', cls: 'warn' };
		if (s.last_status === 'partial') return { label: 'Partiel', cls: 'warn' };
		return { label: 'OK', cls: 'good' };
	}

	$effect(() => {
		load();
	});
</script>

{#if error}<div class="a-error" role="alert">{error}</div>{/if}

<p class="a-muted intro">
	Le collecteur tourne toutes les 15 minutes et interroge chaque source selon sa fréquence. Une source
	<b>faisant autorité</b> publie directement ; les autres alimentent la file « À valider ».
	<b>Tester</b> interroge la source depuis le serveur de production, avec le vrai lecteur, sans rien enregistrer.
</p>

<div class="toolbar">
	<button class="ghost" disabled={probingAll} onclick={probeAll}>{probingAll ? 'Tests en cours…' : '🩺 Tout tester'}</button>
</div>

<table class="a-table">
	<thead>
		<tr>
			<th>Source</th><th>Santé</th><th>Dernier succès</th><th>Nouveaux 24 h</th><th>Échecs 24 h</th><th>Fréquence</th><th
				>Active</th
			><th>Fait autorité</th><th>Diagnostic</th>
		</tr>
	</thead>
	<tbody>
		{#each sources as s (s.code)}
			{@const h = health(s)}
			<tr>
				<td><b>{s.name}</b><br /><code class="a-muted">{s.code}</code></td>
				<td>
					<span class="health {h.cls}">{h.label}</span>
					{#if s.last_error}<div class="error-detail" title={s.last_error}>{s.last_error}</div>{/if}
				</td>
				<td>{dateAndTime(s.last_success_at)}</td>
				<td>{s.new_24h}</td>
				<td>{s.failures_24h}</td>
				<td>{s.poll_minutes} min</td>
				<td><input type="checkbox" checked={s.enabled} onclick={(e) => { e.preventDefault(); toggle(s, 'enabled'); }} aria-label="Activer {s.name}" /></td>
				<td><input type="checkbox" checked={s.authoritative} onclick={(e) => { e.preventDefault(); toggle(s, 'authoritative'); }} aria-label="{s.name} fait autorité" /></td>
				<td><button class="ghost" disabled={probing[s.code]} onclick={() => probe(s.code)}>{probing[s.code] ? '…' : 'Tester'}</button></td>
			</tr>
			{#if reports[s.code]}
				{@const r = reports[s.code]}
				<tr class="report-row">
					<td colspan="9">{@render report(r)}</td>
				</tr>
			{/if}
		{/each}
	</tbody>
</table>

<section class="url-test">
	<h3>Tester une adresse</h3>
	<p class="a-muted">
		Pour une source candidate (CCB, flux d’un éditeur…) : le serveur l’interroge et rapporte statut, type et taille, sans
		afficher le contenu. Adresses HTTPS publiques uniquement.
	</p>
	<form onsubmit={probeUrl}>
		<input type="url" required maxlength="500" placeholder="https://exemple.org/feed.xml" bind:value={testUrl} aria-label="Adresse à tester" />
		<button class="ghost" type="submit" disabled={urlBusy}>{urlBusy ? 'Test…' : 'Tester'}</button>
	</form>
	{#if urlReport}{@render report(urlReport)}{/if}
</section>

{#snippet report(r: ProbeReport)}
	{@const v = VERDICT[r.verdict] ?? { icon: '•', cls: 'off' }}
	<div class="report">
		<div class="verdict {v.cls}">{v.icon} {r.message}</div>
		{#each r.requests as q (q.url)}
			<div class="request a-muted">
				<code>{q.status || 'aucune réponse'}</code>
				{q.format ?? '-'} · {size(q.bytes)} · {q.ms} ms · <span class="req-url">{q.url}</span>
				{#if q.error}<div class="req-error">{q.error}</div>{/if}
			</div>
		{/each}
		{#if r.sample?.length}<div class="sample a-muted">Exemples : {r.sample.join(' · ')}</div>{/if}
	</div>
{/snippet}

<style>
	.toolbar {
		margin: 0 0 12px;
	}
	button {
		border: none;
		border-radius: 6px;
		padding: 6px 12px;
		font-weight: bold;
		font-size: 12px;
		cursor: pointer;
		font-family: inherit;
	}
	button:disabled {
		opacity: 0.6;
		cursor: wait;
	}
	.ghost {
		background: var(--a-surface2);
		color: var(--a-text);
		border: 1px solid var(--a-border);
	}
	.report-row td {
		background: var(--a-surface2);
	}
	.report {
		font-size: 12px;
		margin-top: 6px;
	}
	.verdict {
		font-weight: bold;
		margin-bottom: 4px;
	}
	.request {
		font-size: 11px;
		margin-top: 2px;
	}
	.req-url {
		word-break: break-all;
	}
	.req-error {
		color: var(--a-error);
	}
	.sample {
		font-size: 11px;
		margin-top: 4px;
	}
	.url-test {
		margin-top: 28px;
	}
	.url-test h3 {
		font-size: 15px;
		margin: 0 0 6px;
	}
	.url-test p {
		font-size: 12px;
		margin: 0 0 10px;
	}
	.url-test form {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
	}
	.url-test input {
		flex: 1 1 280px;
		min-width: 0;
		padding: 7px 10px;
		border-radius: 6px;
		border: 1px solid var(--a-border);
		background: var(--a-surface);
		color: var(--a-text);
		font-family: inherit;
	}
	.intro {
		font-size: 13px;
		margin: 0 0 16px;
	}
	.health {
		font-size: 11px;
		font-weight: bold;
		padding: 2px 8px;
		border-radius: 10px;
		background: var(--a-surface2);
	}
	.good {
		color: var(--a-success);
	}
	.warn {
		color: var(--a-warning);
	}
	.bad {
		color: var(--a-error);
	}
	.off {
		color: var(--a-muted);
	}
	.error-detail {
		font-size: 11px;
		color: var(--a-error);
		max-width: 280px;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		margin-top: 4px;
	}
	input[type='checkbox'] {
		width: 16px;
		height: 16px;
		cursor: pointer;
	}
</style>
