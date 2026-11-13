/** Display helpers. All dates come from the API as UTC ISO 8601 strings. */

const dateShort = new Intl.DateTimeFormat('fr-BE', { day: '2-digit', month: '2-digit', year: '2-digit' });
const dateTime = new Intl.DateTimeFormat('fr-BE', {
	day: '2-digit',
	month: '2-digit',
	year: 'numeric',
	hour: '2-digit',
	minute: '2-digit'
});
const integer = new Intl.NumberFormat('fr-BE');

export function shortDate(iso: string | null | undefined): string {
	return iso ? dateShort.format(new Date(iso)) : '-';
}

export function dateAndTime(iso: string | null | undefined): string {
	return iso ? dateTime.format(new Date(iso)) : '-';
}

export function count(n: number | null | undefined): string {
	return n === null || n === undefined ? '-' : integer.format(n);
}

export function percent(value: number | null | undefined, digits = 1): string {
	return value === null || value === undefined ? '-' : `${(value * 100).toFixed(digits)} %`;
}

/** Only http(s) links are ever rendered: blocks javascript:, data:, etc. */
export function safeUrl(url: string | null | undefined): string | null {
	if (!url) return null;
	try {
		const u = new URL(url);
		return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
	} catch {
		return null;
	}
}

export const SEVERITY_LABEL: Record<string, string> = {
	critical: 'Critique',
	high: 'Élevée',
	medium: 'Moyenne',
	low: 'Faible'
};

export const CONFIDENCE_LABEL: Record<string, string> = {
	confirmed: 'Confirmée',
	claimed: 'Revendiquée',
	untrusted: 'Revendication peu fiable'
};

export const LEAK_TYPE_LABEL: Record<string, string> = {
	ransomware: 'Ransomware',
	breach: 'Fuite de données',
	exposure: 'Exposition'
};

export const INTEL_TYPE_LABEL: Record<string, string> = {
	vulnerability: 'Vulnérabilité',
	advisory: 'Avis de sécurité',
	exploitation: 'Exploitation active',
	campaign: 'Campagne'
};

export function cvssClass(score: number): string {
	if (score >= 9) return 'cvss-critical';
	if (score >= 7) return 'cvss-high';
	if (score >= 4) return 'cvss-medium';
	return 'cvss-low';
}

export function impactClass(impact: number): string {
	if (impact >= 5) return 'impact-5';
	if (impact >= 4) return 'impact-4';
	return '';
}
