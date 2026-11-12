/**
 * Typed client for the Risk Studio PHP API.
 * Same origin in production (/api) and through the Vite proxy in dev.
 */

const BASE = '/api/v1';

export interface Health {
	status: 'ok' | 'degraded';
	version: string;
	database: 'ok' | 'unavailable';
	time: string;
}

export interface Category {
	code: string;
	name_fr: string;
	name_en: string;
}

export interface Sector extends Category {
	nis2_annex: 'I' | 'II' | null;
}

export interface Framework {
	code: string;
	name: string;
	short_name: string;
	version: string | null;
	publisher: string | null;
	url: string | null;
	controls_count: number;
}

export interface Reference {
	categories: Category[];
	sectors: Sector[];
	frameworks: Framework[];
}

export interface Risk {
	code: string;
	title: string;
	category: Category;
	threat: string;
	scenario: string;
	measures: string;
	impact: number;
	likelihood: number | null;
	cia: { confidentiality: boolean; integrity: boolean; availability: boolean };
	environment: 'IT' | 'OT' | 'BOTH';
	origin: 'catalogue' | 'community';
	sectors: string[];
	/** `editorial`: written by an editor. `crosswalk`: derived from an editorial ISO mapping. */
	controls: { framework: string; ref: string; source: 'editorial' | 'crosswalk' }[];
	updated_at: string;
	published_at: string | null;
}

export interface Page<T> {
	data: T[];
	meta: { total: number; page: number; per_page: number; pages: number };
}

/** Catalogue filters. In V2 the same shape will come from the user's profile. */
export interface RiskQuery {
	q?: string;
	category?: string;
	sector?: string;
	env?: 'IT' | 'OT';
	framework?: string;
	impact_min?: number;
	/** Requires `framework`. Matches the control and its direct children. */
	control?: string;
	mapping?: 'editorial' | 'all';
	page?: number;
	per_page?: number;
}

export type AssuranceLevel = 'BASIC' | 'IMPORTANT' | 'ESSENTIAL';

export interface Control {
	ref: string;
	label: string | null;
	parent_ref: string | null;
	assurance_level: AssuranceLevel | null;
	key_measure_level: AssuranceLevel | null;
}

export class ApiError extends Error {
	constructor(
		public readonly status: number,
		public readonly code: string,
		message: string
	) {
		super(message);
	}
}

async function request<T>(path: string, fetchFn: typeof fetch = fetch): Promise<T> {
	const response = await fetchFn(BASE + path, { headers: { Accept: 'application/json' } });
	const body = await response.json().catch(() => null);
	if (!response.ok) {
		const error = body?.error ?? {};
		throw new ApiError(response.status, error.code ?? 'http_error', error.message ?? response.statusText);
	}
	return body as T;
}

function toQueryString(query: object): string {
	const params = new URLSearchParams();
	for (const [key, value] of Object.entries(query)) {
		if (value !== undefined && value !== null && value !== '') params.set(key, String(value));
	}
	const qs = params.toString();
	return qs ? `?${qs}` : '';
}

export const api = {
	health: (f?: typeof fetch) => request<Health>('/health', f),
	reference: (f?: typeof fetch) => request<Reference>('/reference', f),
	risks: (query: RiskQuery = {}, f?: typeof fetch) => request<Page<Risk>>(`/risks${toQueryString(query)}`, f),
	controls: (framework: string, f?: typeof fetch) =>
		request<{ framework: string; controls: Control[] }>(
			`/frameworks/${encodeURIComponent(framework)}/controls`,
			f
		),
	risk: (code: string, f?: typeof fetch) =>
		request<{ data: Risk }>(`/risks/${encodeURIComponent(code)}`, f)
};
