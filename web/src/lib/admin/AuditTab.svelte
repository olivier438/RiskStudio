<script lang="ts">
	import { ApiError } from '#lib/api.js';
	import { adminApi, type AuditEntry } from '#lib/admin-api.js';
	import { dateAndTime } from '#lib/format.js';

	let entries = $state<AuditEntry[]>([]);
	let error = $state<string | null>(null);

	$effect(() => {
		adminApi
			.audit()
			.then((r) => (entries = r.data))
			.catch((e) => (error = e instanceof ApiError ? e.message : 'Erreur de chargement.'));
	});

	const details = (d: AuditEntry['details']) =>
		d
			? Object.entries(d)
					.filter(([, v]) => v !== null && v !== '')
					.map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
					.join(' · ')
			: '';
</script>

{#if error}<div class="a-error" role="alert">{error}</div>{/if}

<p class="a-muted intro">Toutes les décisions et connexions, du plus récent au plus ancien (200 dernières entrées).</p>

<table class="a-table">
	<thead><tr><th>Date</th><th>Acteur</th><th>Action</th><th>Objet</th><th>Détails</th></tr></thead>
	<tbody>
		{#each entries as e (e.id)}
			<tr>
				<td class="nowrap">{dateAndTime(e.created_at)}</td>
				<td>{e.actor ?? e.actor_type}</td>
				<td><code>{e.action}</code></td>
				<td>{e.entity}{e.entity_id ? ` ${e.entity_id}` : ''}</td>
				<td class="a-muted details">{details(e.details)}</td>
			</tr>
		{/each}
	</tbody>
</table>

<style>
	.intro {
		font-size: 13px;
		margin: 0 0 16px;
	}
	.nowrap {
		white-space: nowrap;
	}
	.details {
		font-size: 11px;
		word-break: break-word;
	}
</style>
