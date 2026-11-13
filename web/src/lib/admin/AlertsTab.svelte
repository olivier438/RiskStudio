<script lang="ts">
	import { ApiError } from '#lib/api.js';
	import { adminApi, type AdminAlert, type AlertInput } from '#lib/admin-api.js';
	import { ALERT_KIND, ALERT_LEVEL_LABEL, dateAndTime } from '#lib/format.js';

	/** Durations offered for a new alert, in hours (0: no end). */
	const DURATIONS = [
		{ hours: 6, label: '6 heures' },
		{ hours: 24, label: '24 heures' },
		{ hours: 72, label: '3 jours' },
		{ hours: 168, label: '7 jours' },
		{ hours: 0, label: 'Sans fin (à clôturer)' }
	];

	let alerts = $state<AdminAlert[]>([]);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	let fields = $state<Record<string, string>>({});
	let editing = $state<number | null>(null);
	let busy = $state(false);
	let duration = $state(24);
	let form = $state<AlertInput>(empty());

	function empty(): AlertInput {
		return { kind: 'outage', level: 'warning', title: '', summary: '', url: '', starts_at: '', ends_at: '' };
	}

	async function load(): Promise<void> {
		try {
			alerts = (await adminApi.alerts()).data;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Erreur de chargement.';
		}
	}

	function edit(a: AdminAlert): void {
		editing = a.id;
		form = {
			kind: a.kind,
			level: a.level,
			title: a.title,
			summary: a.summary ?? '',
			url: a.url ?? '',
			starts_at: a.starts_at,
			ends_at: a.ends_at ?? ''
		};
		notice = null;
		fields = {};
	}

	function reset(): void {
		editing = null;
		form = empty();
		fields = {};
	}

	async function save(ev: SubmitEvent): Promise<void> {
		ev.preventDefault();
		busy = true;
		error = null;
		fields = {};
		try {
			if (editing !== null) {
				alerts = (await adminApi.editAlert(editing, form)).data;
				notice = 'Alerte mise à jour.';
			} else {
				const ends = duration > 0 ? new Date(Date.now() + duration * 3_600_000).toISOString() : '';
				alerts = (await adminApi.createAlert({ ...form, starts_at: '', ends_at: ends })).data;
				notice = 'Alerte publiée : elle apparaît sur le site au prochain rafraîchissement (une minute au plus).';
			}
			reset();
		} catch (e) {
			if (e instanceof ApiError) {
				fields = e.fields;
				error = e.message;
			} else error = 'Enregistrement impossible.';
		} finally {
			busy = false;
		}
	}

	async function close(a: AdminAlert): Promise<void> {
		if (!confirm(`Clôturer « ${a.title} » ? Elle quitte le site et reste dans l'historique.`)) return;
		try {
			alerts = (await adminApi.closeAlert(a.id)).data;
			notice = 'Alerte clôturée.';
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Action impossible.';
		}
	}

	$effect(() => {
		load();
	});
</script>

{#if error}<div class="a-error" role="alert">{error}</div>{/if}
{#if notice}<div class="a-ok" role="status">{notice}</div>{/if}

<form class="alert-form" onsubmit={save}>
	<h3>{editing !== null ? 'Modifier l’alerte' : '🚨 Nouvelle alerte'}</h3>
	<p class="a-muted hint">
		Pour ce qui compte maintenant et qu'aucun flux ne couvre bien : une panne mondiale, une campagne massive, une
		annonce urgente. Elle s'affiche en haut du site, quelle que soit la vue, jusqu'à sa date de fin.
	</p>
	<div class="grid">
		<label>
			Type
			<select bind:value={form.kind}>
				{#each Object.entries(ALERT_KIND) as [k, v] (k)}<option value={k}>{v.icon} {v.label}</option>{/each}
			</select>
		</label>
		<label>
			Niveau
			<select bind:value={form.level}>
				<option value="info">Info</option>
				<option value="warning">Attention</option>
				<option value="critical">Critique</option>
			</select>
		</label>
		{#if editing === null}
			<label>
				Durée d'affichage
				<select bind:value={duration}>
					{#each DURATIONS as d (d.hours)}<option value={d.hours}>{d.label}</option>{/each}
				</select>
			</label>
		{:else}
			<label>
				Fin (ISO 8601, vide : sans fin)
				<input bind:value={form.ends_at} placeholder="2026-11-14T18:00:00Z" />
				{#if fields.ends_at}<span class="err">{fields.ends_at}</span>{/if}
			</label>
		{/if}
		<label class="wide">
			Titre
			<input required maxlength="200" bind:value={form.title} placeholder="Panne mondiale de Microsoft 365" />
			{#if fields.title}<span class="err">{fields.title}</span>{/if}
		</label>
		<label class="wide">
			Résumé <span class="a-muted">(600 caractères au maximum)</span>
			<textarea rows="3" maxlength="600" bind:value={form.summary}></textarea>
			{#if fields.summary}<span class="err">{fields.summary}</span>{/if}
		</label>
		<label class="wide">
			Lien <span class="a-muted">(facultatif, HTTPS)</span>
			<input type="url" maxlength="2048" bind:value={form.url} placeholder="https://status.exemple.org/" />
			{#if fields.url}<span class="err">{fields.url}</span>{/if}
		</label>
	</div>
	<div class="actions">
		<button type="submit" class="ok" disabled={busy}>{editing !== null ? 'Enregistrer' : 'Publier l’alerte'}</button>
		{#if editing !== null}<button type="button" class="ghost" onclick={reset}>Annuler</button>{/if}
	</div>
</form>

<table class="a-table">
	<thead>
		<tr><th>Alerte</th><th>Niveau</th><th>Début</th><th>Fin</th><th>État</th><th></th></tr>
	</thead>
	<tbody>
		{#each alerts as a (a.id)}
			<tr>
				<td>{ALERT_KIND[a.kind]?.icon} <b>{a.title}</b></td>
				<td class="lvl-{a.level}">{ALERT_LEVEL_LABEL[a.level]}</td>
				<td>{dateAndTime(a.starts_at)}</td>
				<td>{a.ends_at ? dateAndTime(a.ends_at) : 'Sans fin'}</td>
				<td>{a.active ? '🟢 En ligne' : a.status === 'archived' ? 'Clôturée' : 'Programmée ou expirée'}</td>
				<td class="row-actions">
					<button class="link" onclick={() => edit(a)}>Modifier</button>
					{#if a.status === 'published'}<button class="link danger" onclick={() => close(a)}>Clôturer</button>{/if}
				</td>
			</tr>
		{:else}
			<tr><td colspan="6" class="a-muted">Aucune alerte pour l'instant.</td></tr>
		{/each}
	</tbody>
</table>

<style>
	.alert-form {
		background: var(--a-surface);
		border: 1px solid var(--a-border);
		border-radius: 10px;
		padding: 16px;
		margin: 0 0 20px;
	}
	h3 {
		font-size: 15px;
		margin: 0 0 6px;
	}
	.hint {
		font-size: 12px;
		margin: 0 0 14px;
	}
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 12px;
	}
	.wide {
		grid-column: 1 / -1;
	}
	label {
		display: flex;
		flex-direction: column;
		gap: 4px;
		font-size: 12px;
		font-weight: bold;
	}
	input,
	select,
	textarea {
		padding: 7px 10px;
		border-radius: 6px;
		border: 1px solid var(--a-border);
		background: var(--a-bg);
		color: var(--a-text);
		font-family: inherit;
		font-weight: normal;
		min-width: 0;
	}
	.err {
		color: var(--a-error);
		font-weight: normal;
	}
	.actions {
		display: flex;
		gap: 8px;
		margin-top: 14px;
	}
	button {
		border: none;
		border-radius: 6px;
		padding: 7px 12px;
		font-weight: bold;
		font-size: 12px;
		cursor: pointer;
		font-family: inherit;
	}
	.ok {
		background: var(--a-success);
		color: white;
	}
	.ghost {
		background: var(--a-surface2);
		color: var(--a-text);
		border: 1px solid var(--a-border);
	}
	.row-actions {
		white-space: nowrap;
	}
	button.link {
		background: none;
		padding: 0 6px;
		font-weight: normal;
		font-size: 11px;
		color: var(--a-muted);
		text-decoration: underline;
	}
	button.link.danger {
		color: var(--a-error);
	}
	.lvl-critical {
		color: var(--a-error);
		font-weight: bold;
	}
	.lvl-warning {
		color: var(--a-warning);
		font-weight: bold;
	}
</style>
