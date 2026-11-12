import { SvelteMap } from 'svelte/reactivity';

/** Selected items, kept across pages so exports cover every selected row. */
export class Selection<T> {
	readonly items = new SvelteMap<string, T>();

	get size(): number {
		return this.items.size;
	}

	has(key: string): boolean {
		return this.items.has(key);
	}

	toggle(key: string, item: T, on: boolean): void {
		if (on) this.items.set(key, item);
		else this.items.delete(key);
	}

	setMany(entries: [string, T][], on: boolean): void {
		for (const [key, item] of entries) this.toggle(key, item, on);
	}

	values(): T[] {
		return [...this.items.values()];
	}

	clear(): void {
		this.items.clear();
	}
}

/** Local text edits made in edit mode (?edit), applied to exports only. */
export type RiskEdits = { title?: string; scenario?: string; measures?: string };
