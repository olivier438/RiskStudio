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

export interface Source {
	code: string;
	name: string;
}

export interface Reference {
	categories: Category[];
	sectors: Sector[];
	frameworks: Framework[];
	/** Sources that have published content. */
	sources: Source[];
}

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface IntelItem {
	id: number;
	source: Source;
	external_id: string;
	type: 'vulnerability' | 'advisory' | 'exploitation' | 'campaign';
	title: string;
	summary: string | null;
	url: string | null;
	cves: string[];
	cvss: { score: number; vector: string | null } | null;
	epss: { score: number; percentile: number | null } | null;
	kev: boolean;
	kev_due_date: string | null;
	severity: Severity | null;
	/** Known exploited (KEV) or rated critical. */
	critical: boolean;
	score: number | null;
	environment: 'IT' | 'OT' | 'BOTH';
	products: { vendor: string; product: string; environment: string }[];
	categories: string[];
	sectors: string[];
	/** Catalogue risks this item materialises. */
	risks: { code: string; title: string; rule: string }[];
	/** Rules that classified the item: the "why", no AI involved. */
	rule_trace: { rules?: string[] } | null;
	source_published_at: string | null;
	published_at: string | null;
	updated_at: string | null;
}

export interface Leak {
	id: number;
	source: Source;
	type: 'ransomware' | 'breach' | 'exposure';
	organisation: string;
	country: string | null;
	sector: string | null;
	actor: string | null;
	records_count: number | null;
	data_classes: string[];
	/** Computed from the exposed data classes (db/rules/leak_data.csv). */
	severity: 'low' | 'medium' | 'high' | 'critical' | null;
	/** Stated by the source: confirmed, claimed (credible) or untrusted claim. */
	confidence: 'confirmed' | 'claimed' | 'untrusted' | null;
	rule_trace: { rules?: string[] } | null;
	url: string | null;
	disclosed_at: string | null;
	published_at: string | null;
	updated_at: string | null;
}

export interface Stats {
	risks: { total: number };
	intel: {
		total: number;
		critical_recent: number;
		critical_window_days: number;
		latest_id: number | null;
		latest_published_at: string | null;
	};
	leaks: { total: number; latest_id: number | null };
	last_update: string | null;
}

export interface FeedQuery {
	q?: string;
	env?: 'IT' | 'OT';
	severity_min?: Severity;
	kev?: '1';
	source?: string;
	category?: string;
	sector?: string;
	type?: Leak['type'];
	country?: string;
	since?: string;
	page?: number;
	per_page?: number;
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
		message: string,
		/** Per-field messages of a 422 validation error. */
		public readonly fields: Record<string, string> = {}
	) {
		super(message);
	}
}

/** JSON request with a body (POST, PUT). Cookies are sent: same origin. */
export async function send<T>(
	method: 'POST' | 'PUT',
	path: string,
	body: unknown,
	headers: Record<string, string> = {}
): Promise<T> {
	const response = await fetch(BASE + path, {
		method,
		headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...headers },
		body: JSON.stringify(body),
		credentials: 'same-origin'
	});
	const data = await response.json().catch(() => null);
	if (!response.ok) {
		const error = data?.error ?? {};
		throw new ApiError(response.status, error.code ?? 'http_error', error.message ?? response.statusText, error.fields ?? {});
	}
	return data as T;
}

/** GET with cookies and without HTTP cache (back office). */
export async function getPrivate<T>(path: string): Promise<T> {
	const response = await fetch(BASE + path, {
		headers: { Accept: 'application/json' },
		cache: 'no-store',
		credentials: 'same-origin'
	});
	const data = await response.json().catch(() => null);
	if (!response.ok) {
		const error = data?.error ?? {};
		throw new ApiError(response.status, error.code ?? 'http_error', error.message ?? response.statusText);
	}
	return data as T;
}

export interface RiskProposal {
	title: string;
	category: string;
	threat: string;
	scenario: string;
	measures: string;
	impact: number;
	cia: string;
	environment: 'IT' | 'OT' | 'BOTH';
	sectors: string[];
	references?: string;
}

export interface ProposalRequest {
	kind: 'risk' | 'correction';
	payload: RiskProposal | { risk_code: string; message: string };
	submitter_name?: string;
	submitter_email?: string;
	consent?: boolean;
	/** Honeypot: must stay empty. */
	website?: string;
}

async function request<T>(path: string, fetchFn: typeof fetch = fetch): Promise<T> {
	// `no-cache` revalidates with the ETag: an unchanged answer costs a 304.
	const response = await fetchFn(BASE + path, { headers: { Accept: 'application/json' }, cache: 'no-cache' });
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
	stats: (f?: typeof fetch) => request<Stats>('/stats', f),
	intel: (query: FeedQuery = {}, f?: typeof fetch) =>
		request<Page<IntelItem>>(`/intel${toQueryString(query)}`, f),
	leaks: (query: FeedQuery = {}, f?: typeof fetch) => request<Page<Leak>>(`/leaks${toQueryString(query)}`, f),
	controls: (framework: string, f?: typeof fetch) =>
		request<{ framework: string; controls: Control[] }>(
			`/frameworks/${encodeURIComponent(framework)}/controls`,
			f
		),
	risk: (code: string, f?: typeof fetch) =>
		request<{ data: Risk }>(`/risks/${encodeURIComponent(code)}`, f),
	propose: (proposal: ProposalRequest) => send<{ status: 'received' }>('POST', '/proposals', proposal)
};
