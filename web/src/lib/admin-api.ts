/**
 * Back-office client. The session lives in an HttpOnly cookie (invisible to
 * JavaScript); the CSRF token returned at login is kept in memory only and
 * sent with every mutating request.
 */
import { getPrivate, send } from './api.js';

export interface Admin {
	id: number;
	email: string;
	display_name: string;
}

export interface QueueCounts {
	intel: number;
	leaks: number;
	proposals: number;
}

export interface PendingIntel {
	id: number;
	source: string;
	external_id: string;
	type: string;
	title: string;
	summary: string | null;
	url: string | null;
	cvss: number | null;
	epss_percentile: number | null;
	kev: boolean;
	severity: string | null;
	score: number | null;
	environment: string;
	rules: string[];
	source_published_at: string | null;
	created_at: string;
}

export interface PendingLeak {
	id: number;
	source: string;
	type: string;
	organisation: string;
	country: string | null;
	sector: string | null;
	actor: string | null;
	records_count: number | null;
	data_classes: string[];
	severity: string | null;
	confidence: string | null;
	url: string | null;
	disclosed_at: string | null;
	created_at: string;
}

export interface Proposal {
	id: number;
	kind: 'risk' | 'correction';
	payload: Record<string, unknown>;
	submitter_name: string | null;
	submitter_email: string | null;
	status: string;
	admin_note: string | null;
	reviewer: string | null;
	reviewed_at: string | null;
	created_at: string;
}

export interface AdminSource {
	code: string;
	name: string;
	kind: string;
	url: string;
	authoritative: boolean;
	enabled: boolean;
	poll_minutes: number;
	last_run_at: string | null;
	last_success_at: string | null;
	last_status: string | null;
	last_error: string | null;
	new_24h: number;
	failures_24h: number;
	/** Added from the administration (generic RSS or Atom reader). */
	custom: boolean;
	config: SourceSettings | null;
}

export interface SourceSettings {
	family: 'vulnerability' | 'threat';
	country: string | null;
	include: string[];
	exclude: string[];
}

/** What the "Ajouter une source" form sends. Keyword lists are comma-separated. */
export interface CustomSourceInput {
	name: string;
	url: string;
	family: 'vulnerability' | 'threat';
	country: string;
	include: string;
	exclude: string;
	poll_minutes: number;
	authoritative: boolean;
}

export interface PreviewItem {
	title: string;
	date: string | null;
	url: string | null;
	type: string;
	severity: string | null;
	environment: string;
	countries: string[];
	sectors: string[];
	categories: string[];
	risks: string[];
	rules: string[];
}

export interface PreviewReport extends Omit<ProbeReport, 'items'> {
	seen: number;
	kept: number;
	items: PreviewItem[];
}

export interface ProbeRequest {
	url: string;
	status: number;
	content_type: string;
	bytes: number;
	ms: number;
	format: string | null;
	error: string | null;
}

/** Diagnostic run from the production server: verdict and message are ready to show. */
export interface ProbeReport {
	url: string;
	ok: boolean;
	verdict: 'works' | 'reachable' | 'blocked' | 'unreachable' | 'redirect' | 'format' | 'error' | 'refused' | 'no_parser';
	message: string;
	requests: ProbeRequest[];
	items?: number | null;
	sample?: string[];
	location?: string | null;
}

export interface AdminAlert {
	id: number;
	kind: 'outage' | 'attack' | 'vulnerability' | 'other';
	level: 'info' | 'warning' | 'critical';
	title: string;
	summary: string | null;
	url: string | null;
	starts_at: string;
	ends_at: string | null;
	status: 'published' | 'archived';
	active: boolean;
	created_at: string;
}

export interface AlertInput {
	kind: AdminAlert['kind'];
	level: AdminAlert['level'];
	title: string;
	summary: string;
	url: string;
	/** ISO 8601, empty: now. */
	starts_at: string;
	/** ISO 8601, empty: no end. */
	ends_at: string;
}

export interface AdminRisk {
	code: string;
	title: string;
	category: string;
	impact: number;
	environment: string;
	origin: 'catalogue' | 'community';
	status: string;
	updated_at: string;
}

export interface CommunityRisk {
	code: string;
	title: string;
	category: string;
	threat: string;
	scenario: string;
	measures: string;
	impact: number;
	cia: string;
	environment: 'IT' | 'OT' | 'BOTH';
	sectors: string[];
	status: 'published' | 'archived';
}

export interface Statistics {
	risks: Record<string, number>;
	risks_by_origin: Record<string, number>;
	intel: Record<string, number>;
	leaks: Record<string, number>;
	proposals: Record<string, number>;
	intel_by_severity: Record<string, number>;
	top_linked_risks: { code: string; title: string; items: number }[];
	runs_7d: { day: string; runs: number; failed: number; items_new: number }[];
}

export interface AuditEntry {
	id: number;
	actor_type: string;
	actor: string | null;
	action: string;
	entity: string;
	entity_id: string | null;
	details: Record<string, unknown> | null;
	created_at: string;
}

let csrf = '';
const mutate = <T>(method: 'POST' | 'PUT', path: string, body: unknown) =>
	send<T>(method, `/admin${path}`, body, { 'X-CSRF-Token': csrf });

export const adminApi = {
	async login(email: string, password: string, code: string): Promise<Admin> {
		const r = await send<{ admin: Admin; csrf: string }>('POST', '/admin/login', { email, password, code });
		csrf = r.csrf;
		return r.admin;
	},
	async me(): Promise<{ admin: Admin; queue: QueueCounts }> {
		const r = await getPrivate<{ admin: Admin; csrf: string; queue: QueueCounts }>('/admin/me');
		csrf = r.csrf;
		return r;
	},
	logout: () => mutate<{ ok: true }>('POST', '/logout', {}),
	queue: () =>
		getPrivate<{ counts: QueueCounts; intel: PendingIntel[]; leaks: PendingLeak[]; proposals: Proposal[] }>('/admin/queue'),
	proposalsHistory: (status: 'approved' | 'rejected') => getPrivate<{ data: Proposal[] }>(`/admin/proposals?status=${status}`),
	decideIntel: (id: number, decision: 'publish' | 'reject' | 'archive', note?: string) =>
		mutate<{ counts: QueueCounts }>('POST', `/intel/${id}/decision`, { decision, note }),
	decideLeak: (id: number, decision: 'publish' | 'reject' | 'archive', note?: string) =>
		mutate<{ counts: QueueCounts }>('POST', `/leaks/${id}/decision`, { decision, note }),
	decideProposal: (id: number, decision: 'approve' | 'reject', note?: string) =>
		mutate<{ counts: QueueCounts; risk_code: string | null }>('POST', `/proposals/${id}/decision`, { decision, note }),
	risks: () => getPrivate<{ data: AdminRisk[] }>('/admin/risks'),
	risk: (code: string) => getPrivate<{ data: CommunityRisk }>(`/admin/risks/${encodeURIComponent(code)}`),
	updateRisk: (code: string, risk: Omit<CommunityRisk, 'code'>) =>
		mutate<{ data: CommunityRisk }>('PUT', `/risks/${encodeURIComponent(code)}`, risk),
	sources: () => getPrivate<{ data: AdminSource[] }>('/admin/sources'),
	updateSource: (code: string, changes: { enabled?: boolean; authoritative?: boolean }) =>
		mutate<{ data: AdminSource[] }>('POST', `/sources/${encodeURIComponent(code)}`, changes),
	probeSource: (code: string) => mutate<{ data: ProbeReport }>('POST', `/sources/${encodeURIComponent(code)}/probe`, {}),
	probeUrl: (url: string) => mutate<{ data: ProbeReport }>('POST', '/probe', { url }),
	previewSource: (s: CustomSourceInput) => mutate<{ data: PreviewReport }>('POST', '/sources/preview', s),
	createSource: (s: CustomSourceInput) => mutate<{ code: string; data: AdminSource[] }>('POST', '/sources', s),
	editSource: (code: string, s: CustomSourceInput) =>
		mutate<{ data: AdminSource[] }>('PUT', `/sources/${encodeURIComponent(code)}`, s),
	deleteSource: (code: string) => mutate<{ data: AdminSource[] }>('POST', `/sources/${encodeURIComponent(code)}/delete`, {}),
	alerts: () => getPrivate<{ data: AdminAlert[] }>('/admin/alerts'),
	createAlert: (a: AlertInput) => mutate<{ id: number; data: AdminAlert[] }>('POST', '/alerts', a),
	editAlert: (id: number, a: AlertInput) => mutate<{ data: AdminAlert[] }>('PUT', `/alerts/${id}`, a),
	closeAlert: (id: number) => mutate<{ data: AdminAlert[] }>('POST', `/alerts/${id}/close`, {}),
	statistics: () => getPrivate<Statistics>('/admin/statistics'),
	audit: () => getPrivate<{ data: AuditEntry[] }>('/admin/audit?limit=200')
};
