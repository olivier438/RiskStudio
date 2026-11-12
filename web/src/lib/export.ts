/**
 * CSV export, Excel-friendly: UTF-8 BOM, semicolon separator, CRLF.
 * Cells that a spreadsheet would read as a formula are neutralised
 * (CSV injection, OWASP), so an exported risk can never run code in Excel.
 */

export type Cell = string | number | boolean | null | undefined;

export function csvCell(value: Cell): string {
	let text = value === null || value === undefined ? '' : String(value);
	if (typeof value === 'boolean') text = value ? 'OUI' : 'NON';
	if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
	return `"${text.replace(/"/g, '""')}"`;
}

export function toCsv(header: string[], rows: Cell[][]): string {
	return '﻿' + [header, ...rows].map((row) => row.map(csvCell).join(';')).join('\r\n') + '\r\n';
}

export function download(filename: string, content: string, type = 'text/csv;charset=utf-8'): void {
	const url = URL.createObjectURL(new Blob([content], { type }));
	const a = document.createElement('a');
	a.href = url;
	a.download = filename;
	document.body.appendChild(a);
	a.click();
	a.remove();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function exportName(kind: string): string {
	return `RiskStudio_${kind}_${new Date().toISOString().slice(0, 10)}.csv`;
}
