<script lang="ts">
	import { ApiError } from '#lib/api.js';
	import { adminApi, type AdminSource, type CustomSourceInput, type PreviewReport } from '#lib/admin-api.js';
	import { SEVERITY_LABEL, shortDate } from '#lib/format.js';

	let {
		source = null,
		onsaved,
		oncancel
	}: {
		/** The custom source being edited, or null to add one. */
		source?: AdminSource | null;
		onsaved: (sources: AdminSource[], message: string) => void;
		oncancel: () => void;
	} = $props();

	const COUNTRIES = ['', 'BE', 'FR', 'NL', 'LU', 'DE'];

	// svelte-ignore state_referenced_locally
	let form = $state<CustomSourceInput>({
		name: source?.name ?? '',
		url: source?.url ?? '',
		family: source?.config?.family ?? 'threat',
		country: source?.config?.country ?? '',
		include: source?.config?.include.join(', ') ?? '',
		exclude: source?.config?.exclude.join(', ') ?? '',
		poll_minutes: source?.poll_minutes ?? 60,
		authoritative: source?.authoritative ?? false
	});
	let fields = $state<Record<string, string>>({});
	let error = $state<string | null>(null);
	let preview = $state<PreviewReport | null>(null);
	let busy = $state<'' | 'preview' | 'save'>('');

	function fail(e: unknown): void {
		if (e instanceof ApiError) {
			fields = e.fields;
			error = e.message;
		} else error = 'Action impossible.';
	}

	async function runPreview(): Promise<void> {
		busy = 'preview';
		error = null;
		fields = {};
		preview = null;
		try {
			preview = (await adminApi.previewSource({ ...form, poll_minutes: Number(form.poll_minutes) })).data;
		} catch (e) {
			fail(e);
		} finally {
			busy = '';
		}
	}

	async function save(ev: SubmitEvent): Promise<void> {
		ev.preventDefault();
		busy = 'save';
		error = null;
		fields = {};
		try {
			const input = { ...form, poll_minutes: Number(form.poll_minutes) };
			if (source) onsaved((await adminApi.editSource(source.code, input)).data, `${form.name} mise à jour.`);
			else {
				const r = await adminApi.createSource(input);
				onsaved(r.data, `${form.name} ajoutée (${r.code}). Le collecteur la lira à son prochain passage.`);
			}
		} catch (e) {
			fail(e);
		} finally {
			busy = '';
		}
	}
</script>

<form class="source-form" onsubmit={save}>
	<h3>{source ? `Modifier ${source.name}` : '➕ Ajouter une source'}</h3>
	<p class="a-muted hint">
		Un flux RSS ou Atom suffit. Chaque entrée gardée devient une vulnérabilité ou une menace, classée par les règles de
		NOROSHI comme les autres. « Aperçu » lit le flux depuis le serveur, sans rien enregistrer.
	</p>

	<div class="grid">
		<label>
			Nom
			<input required maxlength="60" bind:value={form.name} placeholder="Veille Exemple" />
			{#if fields.name}<span class="err">{fields.name}</span>{/if}
		</label>
		<label class="wide">
			Adresse du flux
			<input required type="url" maxlength="500" bind:value={form.url} placeholder="https://exemple.org/feed.xml" />
			{#if fields.url}<span class="err">{fields.url}</span>{/if}
		</label>
		<label>
			Vue alimentée
			<select bind:value={form.family}>
				<option value="threat">⚡ Menaces (incidents, campagnes)</option>
				<option value="vulnerability">🧩 Vulnérabilités (avis, correctifs)</option>
			</select>
			{#if fields.family}<span class="err">{fields.family}</span>{/if}
		</label>
		<label>
			Pays par défaut
			<select bind:value={form.country}>
				{#each COUNTRIES as c (c)}<option value={c}>{c || 'Aucun (déduit du texte)'}</option>{/each}
			</select>
			{#if fields.country}<span class="err">{fields.country}</span>{/if}
		</label>
		<label class="wide">
			Garder seulement les entrées contenant <span class="a-muted">(facultatif, séparés par des virgules)</span>
			<input bind:value={form.include} placeholder="ransomware, phishing, cyberattaque" />
			{#if fields.include}<span class="err">{fields.include}</span>{/if}
		</label>
		<label class="wide">
			Écarter les entrées contenant <span class="a-muted">(facultatif)</span>
			<input bind:value={form.exclude} placeholder="webinaire, sponsorisé, offre d'emploi" />
			{#if fields.exclude}<span class="err">{fields.exclude}</span>{/if}
		</label>
		<label>
			Fréquence (minutes)
			<input type="number" min="15" max="1440" step="15" bind:value={form.poll_minutes} />
			{#if fields.poll_minutes}<span class="err">{fields.poll_minutes}</span>{/if}
		</label>
		<label class="check">
			<input type="checkbox" bind:checked={form.authoritative} />
			Fait autorité : publier sans validation
		</label>
	</div>

	{#if error}<div class="a-error" role="alert">{error}</div>{/if}

	<div class="actions">
		<button type="button" class="ghost" disabled={busy !== '' || !form.url} onclick={runPreview}
			>{busy === 'preview' ? 'Lecture du flux…' : '👁️ Aperçu'}</button
		>
		<button type="submit" class="ok" disabled={busy !== ''}>{busy === 'save' ? 'Enregistrement…' : 'Enregistrer'}</button>
		<button type="button" class="ghost" onclick={oncancel}>Annuler</button>
	</div>

	{#if preview}
		<div class="preview">
			<div class="verdict" class:good={preview.ok} class:bad={!preview.ok}>{preview.ok ? '✅' : '⛔'} {preview.message}</div>
			{#each preview.items as it (it.url ?? it.title)}
				<div class="item">
					<div>
						<b>{it.title}</b>
						<span class="a-muted">· {shortDate(it.date)}</span>
					</div>
					<div class="a-muted meta">
						{it.severity ? SEVERITY_LABEL[it.severity] : 'Gravité inconnue'} · {it.environment}
						{#if it.countries.length}· {it.countries.join(', ')}{/if}
						{#if it.sectors.length}· {it.sectors.join(', ')}{/if}
						{#if it.categories.length}· {it.categories.join(', ')}{/if}
						{#if it.risks.length}· ↳ {it.risks.join(', ')}{/if}
					</div>
				</div>
			{/each}
			{#if preview.ok && preview.kept > preview.items.length}<div class="a-muted meta">Et {preview.kept - preview.items.length} autre(s).</div>{/if}
		</div>
	{/if}
</form>

<style>
	.source-form {
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
		grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
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
	label.check {
		flex-direction: row;
		align-items: center;
		gap: 8px;
		font-weight: normal;
	}
	input,
	select {
		padding: 7px 10px;
		border-radius: 6px;
		border: 1px solid var(--a-border);
		background: var(--a-bg);
		color: var(--a-text);
		font-family: inherit;
		font-weight: normal;
		min-width: 0;
	}
	input[type='checkbox'] {
		width: 16px;
		height: 16px;
	}
	.err {
		color: var(--a-error);
		font-weight: normal;
	}
	.actions {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
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
	button:disabled {
		opacity: 0.6;
		cursor: wait;
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
	.preview {
		margin-top: 14px;
		font-size: 12px;
	}
	.verdict {
		font-weight: bold;
		margin-bottom: 8px;
	}
	.good {
		color: var(--a-success);
	}
	.bad {
		color: var(--a-error);
	}
	.item {
		padding: 6px 0;
		border-top: 1px solid var(--a-border);
	}
	.meta {
		font-size: 11px;
	}
</style>
