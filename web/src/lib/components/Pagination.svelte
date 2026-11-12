<script lang="ts">
	let {
		page,
		pages,
		total,
		perPage,
		onpage
	}: { page: number; pages: number; total: number; perPage: number; onpage: (p: number) => void } = $props();

	const items = $derived.by(() => {
		const out: (number | 'gap')[] = [];
		for (let i = 1; i <= pages; i++) {
			if (i === 1 || i === pages || Math.abs(i - page) <= 2) out.push(i);
			else if (Math.abs(i - page) === 3) out.push('gap');
		}
		return out;
	});
</script>

{#if pages > 1}
	<nav class="pagination no-print" aria-label="Pagination">
		<div class="pagination-info">
			{(page - 1) * perPage + 1} à {Math.min(page * perPage, total)} sur {total}
		</div>
		<div class="pagination-controls">
			<button class="page-btn" disabled={page === 1} onclick={() => onpage(page - 1)} aria-label="Page précédente"
				>‹</button
			>
			{#each items as it, i (i)}
				{#if it === 'gap'}
					<span class="page-ellipsis">…</span>
				{:else}
					<button class="page-btn" class:active={it === page} aria-current={it === page ? 'page' : undefined} onclick={() => onpage(it)}
						>{it}</button
					>
				{/if}
			{/each}
			<button class="page-btn" disabled={page === pages} onclick={() => onpage(page + 1)} aria-label="Page suivante"
				>›</button
			>
		</div>
	</nav>
{/if}
