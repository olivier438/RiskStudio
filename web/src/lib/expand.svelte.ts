import { SvelteSet } from 'svelte/reactivity';

/** Elements whose click keeps its own meaning and never folds or unfolds a row. */
const INTERACTIVE = 'input, a, button, summary, select, textarea, label, [contenteditable="true"]';

/** Which rows of a table are unfolded. */
export class Expander {
	readonly open = new SvelteSet<string>();

	isOpen(key: string): boolean {
		return this.open.has(key);
	}

	toggle(key: string): void {
		if (this.open.has(key)) this.open.delete(key);
		else this.open.add(key);
	}

	/** Row click: unfolds, unless the click was meant for a control or a text selection. */
	onRowClick(event: MouseEvent, key: string): void {
		const target = event.target as HTMLElement | null;
		if (target?.closest(INTERACTIVE)) return;
		if (window.getSelection()?.toString()) return;
		this.toggle(key);
	}
}
