<script lang="ts">
	import type { Reference } from '#lib/api.js';
	import type { CyberFilters, GrcFilters, LeakFilters, Mode } from '#lib/filters.js';

	let {
		mode,
		reference,
		grc = $bindable(),
		cyber = $bindable(),
		leaks = $bindable(),
		onchange,
		onreset
	}: {
		mode: Mode;
		reference: Reference;
		grc: GrcFilters;
		cyber: CyberFilters;
		leaks: LeakFilters;
		/** Called after any change; `debounce` is true while typing in the search box. */
		onchange: (debounce: boolean) => void;
		onreset: () => void;
	} = $props();

	const PLACEHOLDER: Record<Mode, string> = {
		grc: '🔍 Chercher par mot-clé, menace, code de risque...',
		cyber: '🔍 Chercher par mot-clé, CVE, éditeur, produit...',
		leaks: '🔍 Chercher par organisation ou groupe...'
	};

	const LEAK_COUNTRIES = ['BE', 'FR', 'NL', 'LU', 'DE'];
	const changed = () => onchange(false);
</script>

<div class="toolbar no-print">
	{#if mode === 'grc'}
		<input
			class="search-input"
			type="search"
			placeholder={PLACEHOLDER.grc}
			aria-label="Recherche"
			maxlength="120"
			bind:value={grc.q}
			oninput={() => onchange(true)}
		/>
		<select bind:value={grc.env} onchange={changed} aria-label="Environnement">
			<option value="">Tous les environnements</option>
			<option value="IT">💻 Environnement IT</option>
			<option value="OT">⚙️ Environnement OT</option>
		</select>
		<select bind:value={grc.sector} onchange={changed} aria-label="Secteur">
			<option value="">Tous les secteurs</option>
			{#each reference.sectors as s (s.code)}<option value={s.code}>{s.name_fr}</option>{/each}
		</select>
		<select bind:value={grc.category} onchange={changed} aria-label="Catégorie">
			<option value="">Toutes les catégories</option>
			{#each reference.categories as c (c.code)}<option value={c.code}>{c.name_fr}</option>{/each}
		</select>
		<select bind:value={grc.framework} onchange={changed} aria-label="Référentiel">
			<option value="">Tous les référentiels</option>
			{#each reference.frameworks as f (f.code)}<option value={f.code}>{f.short_name} {f.version ?? ''}</option>{/each}
		</select>
		{#if grc.framework}
			<label class="check">
				<input
					type="checkbox"
					checked={grc.mapping === 'editorial'}
					onchange={(e) => {
						grc.mapping = e.currentTarget.checked ? 'editorial' : '';
						changed();
					}}
				/>
				Éditorial seulement
			</label>
		{/if}
		<select bind:value={grc.impact_min} onchange={changed} aria-label="Impact minimum">
			<option value="">Tous les impacts</option>
			<option value="5">Impact 5 : critique</option>
			<option value="4">Impact 4 et plus</option>
			<option value="3">Impact 3 et plus</option>
			<option value="2">Impact 2 et plus</option>
		</select>
	{:else if mode === 'cyber'}
		<input
			class="search-input"
			type="search"
			placeholder={PLACEHOLDER.cyber}
			aria-label="Recherche"
			maxlength="120"
			bind:value={cyber.q}
			oninput={() => onchange(true)}
		/>
		<select bind:value={cyber.env} onchange={changed} aria-label="Environnement">
			<option value="">Tous les environnements</option>
			<option value="IT">💻 Environnement IT</option>
			<option value="OT">⚙️ Environnement OT</option>
		</select>
		<select bind:value={cyber.severity_min} onchange={changed} aria-label="Sévérité minimum">
			<option value="">Toutes les sévérités</option>
			<option value="critical">Critique</option>
			<option value="high">Élevée et plus</option>
			<option value="medium">Moyenne et plus</option>
		</select>
		<label class="check">
			<input
				type="checkbox"
				checked={cyber.kev === '1'}
				onchange={(e) => {
					cyber.kev = e.currentTarget.checked ? '1' : '';
					changed();
				}}
			/>
			Exploitée (KEV)
		</label>
		<select bind:value={cyber.sector} onchange={changed} aria-label="Secteur">
			<option value="">Tous les secteurs</option>
			{#each reference.sectors as s (s.code)}<option value={s.code}>{s.name_fr}</option>{/each}
		</select>
		<select bind:value={cyber.category} onchange={changed} aria-label="Catégorie">
			<option value="">Toutes les catégories</option>
			{#each reference.categories as c (c.code)}<option value={c.code}>{c.name_fr}</option>{/each}
		</select>
		<select bind:value={cyber.source} onchange={changed} aria-label="Source">
			<option value="">Toutes les sources</option>
			{#each reference.sources as s (s.code)}<option value={s.code}>{s.name}</option>{/each}
		</select>
	{:else}
		<input
			class="search-input"
			type="search"
			placeholder={PLACEHOLDER.leaks}
			aria-label="Recherche"
			maxlength="120"
			bind:value={leaks.q}
			oninput={() => onchange(true)}
		/>
		<select bind:value={leaks.type} onchange={changed} aria-label="Type">
			<option value="">Tous les types</option>
			<option value="ransomware">Ransomware</option>
			<option value="breach">Fuite de données</option>
			<option value="exposure">Exposition</option>
		</select>
		<select bind:value={leaks.country} onchange={changed} aria-label="Pays">
			<option value="">Tous les pays</option>
			{#each LEAK_COUNTRIES as c (c)}<option value={c}>{c}</option>{/each}
		</select>
		<select bind:value={leaks.sector} onchange={changed} aria-label="Secteur">
			<option value="">Tous les secteurs</option>
			{#each reference.sectors as s (s.code)}<option value={s.code}>{s.name_fr}</option>{/each}
		</select>
		<select bind:value={leaks.source} onchange={changed} aria-label="Source">
			<option value="">Toutes les sources</option>
			{#each reference.sources as s (s.code)}<option value={s.code}>{s.name}</option>{/each}
		</select>
	{/if}
	<button class="reset" onclick={onreset} title="Réinitialiser les filtres">↺</button>
</div>

<style>
	.toolbar {
		background: var(--surface);
		padding: 15px;
		border-radius: 12px;
		display: flex;
		gap: 10px;
		margin-bottom: 20px;
		align-items: center;
		box-shadow: var(--shadow-md);
		flex-wrap: wrap;
	}
	.search-input {
		flex-grow: 1;
		min-width: 200px;
		padding: 10px;
		border: 1px solid var(--border);
		border-radius: 6px;
		outline: none;
		font-size: 13px;
		font-family: inherit;
	}
	.search-input:focus {
		border-color: var(--primary);
	}
	select {
		padding: 10px;
		border-radius: 6px;
		border: 1px solid var(--border);
		cursor: pointer;
		font-size: 13px;
		font-family: inherit;
		background: var(--surface);
		max-width: 220px;
	}
	.check {
		font-size: 12px;
		color: var(--muted-strong);
		display: flex;
		align-items: center;
		gap: 5px;
		white-space: nowrap;
	}
	.reset {
		border: 1px solid var(--border);
		background: var(--surface);
		border-radius: 6px;
		padding: 8px 12px;
		cursor: pointer;
		font-size: 15px;
		color: var(--muted);
	}
	.reset:hover {
		color: var(--primary);
		border-color: var(--primary);
	}
	@media (max-width: 768px) {
		.toolbar {
			flex-direction: column;
			align-items: stretch;
		}
		select {
			max-width: none;
		}
	}
</style>
