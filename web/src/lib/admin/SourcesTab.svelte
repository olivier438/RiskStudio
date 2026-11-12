<script lang="ts">
	import { ApiError } from '#lib/api.js';
	import { adminApi, type AdminSource } from '#lib/admin-api.js';
	import { dateAndTime } from '#lib/format.js';

	let sources = $state<AdminSource[]>([]);
	let error = $state<string | null>(null);

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
</p>

<table class="a-table">
	<thead>
		<tr>
			<th>Source</th><th>Santé</th><th>Dernier succès</th><th>Nouveaux 24 h</th><th>Échecs 24 h</th><th>Fréquence</th><th
				>Active</th
			><th>Fait autorité</th>
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
			</tr>
		{/each}
	</tbody>
</table>

<style>
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
