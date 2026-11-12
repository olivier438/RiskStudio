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
	statistics: () => getPrivate<Statistics>('/admin/statistics'),
	audit: () => getPrivate<{ data: AuditEntry[] }>('/admin/audit?limit=200')
};
