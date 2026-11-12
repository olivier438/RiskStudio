<script lang="ts">
	import type { Reference } from '#lib/api.js';
	import { ApiError } from '#lib/api.js';
	import { adminApi, type AdminRisk, type CommunityRisk } from '#lib/admin-api.js';
	import { shortDate } from '#lib/format.js';

	let { reference }: { reference: Reference } = $props();

	let risks = $state<AdminRisk[]>([]);
	let filter = $state('');
	let originFilter = $state<'' | 'catalogue' | 'community'>('');
	let editing = $state<CommunityRisk | null>(null);
	let fields = $state<Record<string, string>>({});
	let error = $state<string | null>(null);
	let saved = $state<string | null>(null);

	const shown = $derived(
		risks.filter(
			(r) =>
				(!originFilter || r.origin === originFilter) &&
				(!filter || `${r.code} ${r.title}`.toLowerCase().includes(filter.toLowerCase()))
		)
	);

	async function load(): Promise<void> {
		try {
			risks = (await adminApi.risks()).data;
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Erreur de chargement.';
		}
	}

	async function edit(code: string): Promise<void> {
		fields = {};
		saved = null;
		editing = (await adminApi.risk(code)).data;
	}

	async function save(event: SubmitEvent): Promise<void> {
		event.preventDefault();
		if (!editing) return;
		const { code, ...risk } = editing;
		try {
			editing = (await adminApi.updateRisk(code, { ...risk, impact: Number(risk.impact) })).data;
			saved = `${code} enregistré.`;
			fields = {};
			await load();
		} catch (e) {
			if (e instanceof ApiError) {
				fields = e.fields;
				error = e.message;
			}
		}
	}

	$effect(() => {
		load();
	});
</script>

{#if error}<div class="a-error" role="alert">{error}</div>{/if}

<p class="a-muted intro">
	Les risques du <b>catalogue</b> se modifient dans <code>db/catalogue/risks.csv</code> (source de vérité, importée par
	<code>make catalogue</code>). Les risques <b>communautaires</b>, issus de propositions approuvées, se modifient ici.
</p>

<div class="tools">
	<input type="search" placeholder="Filtrer par code ou titre" bind:value={filter} />
	<select bind:value={originFilter}>
		<option value="">Toutes origines</option>
		<option value="catalogue">Catalogue</option>
		<option value="community">Communauté</option>
	</select>
	<span class="a-muted">{shown.length} risque(s)</span>
</div>

{#if editing}
	<form class="editor" onsubmit={save}>
		<h3>Modifier {editing.code}</h3>
		<label>Titre <input bind:value={editing.title} maxlength="255" /></label>
		{#if fields.title}<div class="err">{fields.title}</div>{/if}
		<div class="row">
			<label
				>Catégorie
				<select bind:value={editing.category}>
					{#each reference.categories as c (c.code)}<option value={c.code}>{c.name_fr}</option>{/each}
				</select>
			</label>
			<label>Menace <input bind:value={editing.threat} maxlength="255" /></label>
		</div>
		<label>Scénario <textarea bind:value={editing.scenario} maxlength="2000"></textarea></label>
		{#if fields.scenario}<div class="err">{fields.scenario}</div>{/if}
		<label>Mesures <textarea bind:value={editing.measures} maxlength="2000"></textarea></label>
		{#if fields.measures}<div class="err">{fields.measures}</div>{/if}
		<div class="row">
			<label
				>Impact
				<select bind:value={editing.impact}>{#each [1, 2, 3, 4, 5] as n (n)}<option value={n}>{n}</option>{/each}</select>
			</label>
			<label>CIA <input bind:value={editing.cia} maxlength="3" placeholder="CIA" /></label>
			<label
				>Environnement
				<select bind:value={editing.environment}>
					<option value="IT">IT</option><option value="OT">OT</option><option value="BOTH">IT et OT</option>
				</select>
			</label>
			<label
				>Statut
				<select bind:value={editing.status}>
					<option value="published">Publié</option><option value="archived">Archivé</option>
				</select>
			</label>
		</div>
		{#if fields.cia}<div class="err">{fields.cia}</div>{/if}
		<label
			>Secteurs (aucun = tous)
			<select multiple size="5" bind:value={editing.sectors}>
				{#each reference.sectors as s (s.code)}<option value={s.code}>{s.name_fr}</option>{/each}
			</select>
		</label>
		<div class="actions">
			<button class="ok" type="submit">Enregistrer</button>
			<button class="ghost" type="button" onclick={() => (editing = null)}>Fermer</button>
			{#if saved}<span class="a-ok-inline">{saved}</span>{/if}
		</div>
	</form>
{/if}

<table class="a-table">
	<thead>
		<tr><th>Code</th><th>Titre</th><th>Catégorie</th><th>Impact</th><th>Origine</th><th>Statut</th><th>Mise à jour</th><th></th></tr>
	</thead>
	<tbody>
		{#each shown as r (r.code)}
			<tr>
				<td><code>{r.code}</code></td>
				<td>{r.title}</td>
				<td>{r.category}</td>
				<td>{r.impact}/5</td>
				<td>{r.origin === 'community' ? '👥 Communauté' : '📚 Catalogue'}</td>
				<td><span class="status status-{r.status}">{r.status}</span></td>
				<td>{shortDate(r.updated_at)}</td>
				<td>{#if r.origin === 'community'}<button class="ghost" onclick={() => edit(r.code)}>Modifier</button>{/if}</td>
			</tr>
		{/each}
	</tbody>
</table>

<style>
	.intro {
		font-size: 13px;
		margin: 0 0 16px;
	}
	.tools {
		display: flex;
		gap: 10px;
		align-items: center;
		margin-bottom: 14px;
		flex-wrap: wrap;
	}
	input,
	select,
	textarea {
		background: var(--a-surface2);
		border: 1px solid var(--a-border);
		color: var(--a-text);
		border-radius: 6px;
		padding: 8px 10px;
		font-family: inherit;
		font-size: 13px;
	}
	.tools input {
		min-width: 260px;
	}
	.editor {
		background: var(--a-surface);
		border: 1px solid var(--primary);
		border-radius: 12px;
		padding: 18px;
		margin-bottom: 18px;
		display: grid;
		gap: 10px;
	}
	.editor h3 {
		margin: 0;
		font-size: 15px;
	}
	.editor label {
		display: grid;
		gap: 4px;
		font-size: 12px;
		color: var(--a-muted);
	}
	.editor textarea {
		min-height: 70px;
		resize: vertical;
	}
	.row {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
		gap: 10px;
	}
	.err {
		color: var(--a-error);
		font-size: 12px;
	}
	.actions {
		display: flex;
		gap: 10px;
		align-items: center;
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
	.status {
		font-size: 11px;
		padding: 2px 7px;
		border-radius: 8px;
		background: var(--a-surface2);
	}
	.status-published {
		color: var(--a-success);
	}
	.status-archived {
		color: var(--a-muted);
	}
</style>
