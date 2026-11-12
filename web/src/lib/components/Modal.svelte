<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		open = $bindable(false),
		title,
		children,
		footer
	}: { open: boolean; title: string; children: Snippet; footer?: Snippet } = $props();

	let dialog: HTMLDialogElement | undefined = $state();

	$effect(() => {
		if (!dialog) return;
		if (open && !dialog.open) dialog.showModal();
		if (!open && dialog.open) dialog.close();
	});
</script>

<!-- Native <dialog>: focus trap, Escape key and inert background for free. -->
<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
<dialog
	bind:this={dialog}
	class="modal-box no-print"
	aria-label={title}
	onclose={() => (open = false)}
	onclick={(e) => {
		if (e.target === dialog) open = false;
	}}
>
	<div class="modal-header">
		<h2>{title}</h2>
		<button class="modal-close" onclick={() => (open = false)} aria-label="Fermer">✕</button>
	</div>
	<div class="modal-body">
		{@render children()}
	</div>
	{#if footer}
		<div class="modal-footer">{@render footer()}</div>
	{/if}
</dialog>

<style>
	.modal-box {
		border: none;
		padding: 0;
		border-radius: 16px;
		max-width: 640px;
		width: 90%;
		max-height: 85vh;
		box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
		animation: modalIn 0.2s ease;
	}
	.modal-box::backdrop {
		background: rgba(15, 23, 42, 0.6);
		backdrop-filter: blur(3px);
	}
	@keyframes modalIn {
		from {
			transform: translateY(20px);
			opacity: 0;
		}
		to {
			transform: translateY(0);
			opacity: 1;
		}
	}
	.modal-header {
		padding: 24px 28px 0;
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
	}
	.modal-header h2 {
		margin: 0;
		font-size: 20px;
		color: var(--primary);
	}
	.modal-close {
		background: none;
		border: none;
		font-size: 22px;
		cursor: pointer;
		color: #94a3b8;
		padding: 0;
		line-height: 1;
	}
	.modal-close:hover {
		color: var(--text);
	}
	.modal-body {
		padding: 20px 28px 28px;
		font-size: 14px;
		line-height: 1.7;
		color: #334155;
	}
	.modal-body :global(h3) {
		font-size: 13px;
		text-transform: uppercase;
		letter-spacing: 0.5px;
		color: var(--muted);
		margin: 20px 0 8px;
	}
	.modal-body :global(p) {
		margin: 0 0 12px;
	}
	.modal-body :global(ul) {
		margin: 0 0 12px;
		padding-left: 20px;
	}
	.modal-body :global(li) {
		margin-bottom: 4px;
	}
	.modal-body :global(.modal-tag) {
		display: inline-block;
		padding: 3px 8px;
		border-radius: 4px;
		font-size: 11px;
		font-weight: bold;
		background: #dbeafe;
		color: #1e40af;
		margin: 2px;
	}
	.modal-body :global(.date) {
		font-size: 11px;
		color: #94a3b8;
		font-weight: normal;
		text-transform: none;
		letter-spacing: 0;
	}
	.modal-footer {
		padding: 16px 28px;
		border-top: 1px solid var(--border);
		background: var(--bg);
		font-size: 12px;
		color: #94a3b8;
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 12px;
	}
	.modal-footer :global(a) {
		color: var(--primary);
		font-weight: bold;
		text-decoration: none;
	}
</style>
