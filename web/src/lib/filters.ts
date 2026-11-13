/**
 * Filters of each view, and their round trip through the URL query string so
 * that a filtered view can be shared as a link (?mode=cyber&kev=1...).
 */
import type { FeedQuery, RiskQuery } from './api.js';

/** `cyber` is the vulnerabilities view (id kept so that shared links still work). */
export type Mode = 'grc' | 'cyber' | 'threats' | 'leaks';
export const MODES: Mode[] = ['grc', 'cyber', 'threats', 'leaks'];

export interface GrcFilters {
	q: string;
	env: '' | 'IT' | 'OT';
	sector: string;
	category: string;
	framework: string;
	mapping: '' | 'editorial';
	impact_min: string;
}

export interface CyberFilters {
	q: string;
	env: '' | 'IT' | 'OT';
	severity_min: '' | 'medium' | 'high' | 'critical';
	kev: '' | '1';
	source: string;
	category: string;
	sector: string;
}

export interface ThreatFilters {
	q: string;
	env: '' | 'IT' | 'OT';
	severity_min: '' | 'medium' | 'high' | 'critical';
	country: string;
	sector: string;
	category: string;
	source: string;
}

export interface LeakFilters {
	q: string;
	type: '' | 'ransomware' | 'breach' | 'exposure';
	country: string;
	sector: string;
	source: string;
}

export interface ViewState {
	mode: Mode;
	page: number;
	grc: GrcFilters;
	cyber: CyberFilters;
	threats: ThreatFilters;
	leaks: LeakFilters;
}

export const emptyGrc = (): GrcFilters => ({
	q: '',
	env: '',
	sector: '',
	category: '',
	framework: '',
	mapping: '',
	impact_min: ''
});
export const emptyCyber = (): CyberFilters => ({
	q: '',
	env: '',
	severity_min: '',
	kev: '',
	source: '',
	category: '',
	sector: ''
});
export const emptyThreats = (): ThreatFilters => ({
	q: '',
	env: '',
	severity_min: '',
	country: '',
	sector: '',
	category: '',
	source: ''
});
export const emptyLeaks = (): LeakFilters => ({ q: '', type: '', country: '', sector: '', source: '' });

function pick<T extends object>(params: URLSearchParams, empty: T): T {
	const out = { ...empty } as Record<string, string>;
	for (const key of Object.keys(empty)) {
		const value = params.get(key);
		if (value !== null) out[key] = value.slice(0, 120);
	}
	return out as T;
}

export function fromUrl(url: URL): ViewState {
	const p = url.searchParams;
	const mode = (MODES as string[]).includes(p.get('mode') ?? '') ? (p.get('mode') as Mode) : 'grc';
	const page = Math.max(1, Math.min(10_000, parseInt(p.get('page') ?? '1', 10) || 1));
	return {
		mode,
		page,
		grc: mode === 'grc' ? pick(p, emptyGrc()) : emptyGrc(),
		cyber: mode === 'cyber' ? pick(p, emptyCyber()) : emptyCyber(),
		threats: mode === 'threats' ? pick(p, emptyThreats()) : emptyThreats(),
		leaks: mode === 'leaks' ? pick(p, emptyLeaks()) : emptyLeaks()
	};
}

/** Only the active view's non-empty filters end up in the URL. */
export function toSearch(state: ViewState, keep: URLSearchParams): string {
	const params = new URLSearchParams();
	if (state.mode !== 'grc') params.set('mode', state.mode);
	for (const [key, value] of Object.entries(state[state.mode])) {
		if (value) params.set(key, value);
	}
	if (state.page > 1) params.set('page', String(state.page));
	if (keep.has('edit')) params.set('edit', '');
	const s = params.toString();
	return s ? `?${s}` : '';
}

export function grcQuery(f: GrcFilters, page: number, perPage: number): RiskQuery {
	return {
		q: f.q || undefined,
		env: f.env || undefined,
		sector: f.sector || undefined,
		category: f.category || undefined,
		framework: f.framework || undefined,
		mapping: f.framework && f.mapping ? 'editorial' : undefined,
		impact_min: f.impact_min ? Number(f.impact_min) : undefined,
		page,
		per_page: perPage
	};
}

export function cyberQuery(f: CyberFilters, page: number, perPage: number): FeedQuery {
	return {
		q: f.q || undefined,
		env: f.env || undefined,
		severity_min: f.severity_min || undefined,
		kev: f.kev || undefined,
		source: f.source || undefined,
		category: f.category || undefined,
		sector: f.sector || undefined,
		kind: 'vulnerability',
		page,
		per_page: perPage
	};
}

export function threatQuery(f: ThreatFilters, page: number, perPage: number): FeedQuery {
	return {
		q: f.q || undefined,
		env: f.env || undefined,
		severity_min: f.severity_min || undefined,
		country: f.country || undefined,
		sector: f.sector || undefined,
		category: f.category || undefined,
		source: f.source || undefined,
		kind: 'threat',
		page,
		per_page: perPage
	};
}

export function leakQuery(f: LeakFilters, page: number, perPage: number): FeedQuery {
	return {
		q: f.q || undefined,
		type: f.type || undefined,
		country: f.country || undefined,
		sector: f.sector || undefined,
		source: f.source || undefined,
		page,
		per_page: perPage
	};
}
