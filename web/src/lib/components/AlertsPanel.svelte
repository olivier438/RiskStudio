<script lang="ts">
	import type { Alert } from '#lib/api.js';
	import { ALERT_KIND, ALERT_LEVEL_LABEL, dateAndTime, safeUrl } from '#lib/format.js';

	let { alerts, onclose }: { alerts: Alert[]; onclose: () => void } = $props();
</script>

<section class="alerts no-print" aria-label="Alertes en cours">
	<header>
		<h2>🚨 Alertes en cours</h2>
		<button class="close" onclick={onclose} aria-label="Masquer les alertes">✕</button>
	</header>
	{#each alerts as a (a.id)}
		{@const url = safeUrl(a.url)}
		<article class="alert level-{a.level}">
			<div class="head">
				<span class="kind">{ALERT_KIND[a.kind]?.icon} {ALERT_KIND[a.kind]?.label}</span>
				<span class="level">{ALERT_LEVEL_LABEL[a.level]}</span>
				<span class="when">depuis le {dateAndTime(a.starts_at)}</span>
			</div>
			<h3>{a.title}</h3>
			{#if a.summary}<p>{a.summary}</p>{/if}
			{#if url}<a class="link" href={url} target="_blank" rel="noopener noreferrer">🔗 En savoir plus</a>{/if}
		</article>
	{:else}
		<p class="none">Aucune alerte en cours. Tout est calme, profitez-en.</p>
	{/each}
</section>

<style>
	.alerts {
		background: var(--surface);
		border-radius: 10px;
		box-shadow: var(--shadow-sm);
		padding: 14px 16px;
		margin-bottom: 20px;
		border-top: 4px solid #dc2626;
	}
	header {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}
	h2 {
		margin: 0 0 8px;
		font-size: 15px;
	}
	.close {
		background: none;
		border: none;
		cursor: pointer;
		color: var(--muted);
		font-size: 14px;
	}
	.alert {
		border-left: 4px solid #94a3b8;
		padding: 8px 12px;
		margin-top: 8px;
		border-radius: 4px;
		background: #f8fafc;
	}
	.alert.level-warning {
		border-left-color: #ea580c;
		background: #fff7ed;
	}
	.alert.level-critical {
		border-left-color: #dc2626;
		background: #fef2f2;
	}
	.head {
		display: flex;
		gap: 10px;
		flex-wrap: wrap;
		font-size: 11px;
		color: var(--muted);
	}
	.kind {
		font-weight: 600;
		color: var(--muted-strong);
	}
	.level {
		font-weight: 700;
	}
	.level-critical .level {
		color: #b91c1c;
	}
	.level-warning .level {
		color: #c2410c;
	}
	h3 {
		margin: 4px 0;
		font-size: 14px;
	}
	p {
		margin: 0 0 4px;
		font-size: 13px;
	}
	.none {
		font-size: 13px;
		color: var(--muted);
		margin: 0;
	}
</style>
