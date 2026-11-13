<script lang="ts">
	import { ApiError } from '#lib/api.js';
	import QRCode from 'qrcode';

	interface Status {
		installed: boolean;
		migrations_applied: number;
		migrations_pending: string[];
		risks: number;
		admins: number;
		php: string;
	}

	let token = $state('');
	let status = $state<Status | null>(null);
	let log = $state<string[]>([]);
	let error = $state<string | null>(null);
	let busy = $state(false);
	let admin = $state({ email: '', name: '', password: '' });
	// Schema owner of the database: sent for one request, never stored.
	let owner = $state({ user: '', password: '' });
	let fields = $state<Record<string, string>>({});
	let totp = $state<{ secret: string; uri: string; qr: string } | null>(null);
	let reset = $state({ email: '', password: '' });
	let probe = $state('');
	let probeResult = $state<'ok' | 'ko' | null>(null);

	/** Generated in the browser: an SVG of paths only (no inline style, CSP-safe). */
	async function showTotp(secret: string, uri: string): Promise<void> {
		const qr = await QRCode.toString(uri, { type: 'svg', margin: 1, errorCorrectionLevel: 'M' });
		totp = { secret, uri, qr };
		probe = '';
		probeResult = null;
	}

	function base32(text: string): Uint8Array<ArrayBuffer> {
		const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		let bits = '';
		for (const c of text.replace(/[\s=]/g, '').toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
		const bytes = new Uint8Array(new ArrayBuffer(Math.floor(bits.length / 8)));
		for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
		return bytes;
	}

	/** Checks, in the browser only, that the authenticator app shows the right codes. */
	async function checkProbe(): Promise<void> {
		if (!totp) return;
		const key = await crypto.subtle.importKey('raw', base32(totp.secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
		const now = Math.floor(Date.now() / 30000);
		const code = probe.replace(/\s/g, '');
		for (const step of [now - 1, now, now + 1]) {
			const msg = new DataView(new ArrayBuffer(8));
			msg.setUint32(4, step);
			const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg.buffer));
			const o = h[19] & 0xf;
			const v = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1_000_000;
			if (String(v).padStart(6, '0') === code) {
				probeResult = 'ok';
				return;
			}
		}
		probeResult = 'ko';
	}

	async function call<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
		const response = await fetch(`/api/v1/setup${path}`, {
			method,
			headers: { 'X-Setup-Token': token, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
			body: body ? JSON.stringify(body) : undefined,
			cache: 'no-store'
		});
		const data = await response.json().catch(() => null);
		if (!response.ok) {
			if (response.status === 404) throw new ApiError(404, 'disabled', 'Installation désactivée : SETUP_TOKEN absent ou trop court dans .env.');
			throw new ApiError(response.status, data?.error?.code ?? 'error', data?.error?.message ?? response.statusText, data?.error?.fields ?? {});
		}
		return data as T;
	}

	async function run(action: () => Promise<void>): Promise<void> {
		busy = true;
		error = null;
		try {
			await action();
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Impossible de joindre l’API. Vérifiez que le dossier de l’application est bien envoyé.';
			if (e instanceof ApiError) fields = e.fields;
		} finally {
			busy = false;
		}
	}

	const check = () =>
		run(async () => {
			status = await call<Status>('GET', '/status');
		});
	const install = () =>
		run(async () => {
			fields = {};
			try {
				log = (await call<{ log: string[] }>('POST', '/install', { db_admin_user: owner.user, db_admin_password: owner.password })).log;
			} finally {
				owner.password = '';
			}
			status = await call<Status>('GET', '/status');
		});
	const createAdmin = (event: SubmitEvent) => {
		event.preventDefault();
		return run(async () => {
			fields = {};
			const r = await call<{ totp_secret: string; totp_uri: string }>('POST', '/admin', admin);
			await showTotp(r.totp_secret, r.totp_uri);
			admin.password = '';
			status = await call<Status>('GET', '/status');
		});
	};
	const resetTotp = (event: SubmitEvent) => {
		event.preventDefault();
		return run(async () => {
			const r = await call<{ totp_secret: string; totp_uri: string }>('POST', '/admin/reset', reset);
			reset.password = '';
			await showTotp(r.totp_secret, r.totp_uri);
		});
	};
</script>

<svelte:head>
	<title>NOROSHI | Installation</title>
	<meta name="robots" content="noindex, nofollow" />
</svelte:head>

<div class="page">
	<h1>🛡️ Installation de NOROSHI</h1>
	<p class="muted">
		Cet assistant fonctionne seulement tant que <code>SETUP_TOKEN</code> est présent dans le fichier
		<code>.env</code> du serveur. Retirez-le une fois l'installation terminée.
	</p>

	<section class="card">
		<h2>1. Jeton d'installation</h2>
		<div class="row">
			<input type="password" autocomplete="off" placeholder="SETUP_TOKEN" bind:value={token} aria-label="Jeton d'installation" />
			<button onclick={check} disabled={busy || token.length < 32}>Vérifier</button>
		</div>
		{#if token && token.length < 32}<p class="muted small">32 caractères au minimum.</p>{/if}
	</section>

	{#if error}<div class="error-msg" role="alert">{error}</div>{/if}

	{#if status}
		<section class="card">
			<h2>2. Base de données</h2>
			<ul>
				<li>PHP {status.php}</li>
				<li>
					Schéma :
					{#if !status.installed}<b>pas encore installé</b>
					{:else if status.migrations_pending.length}<b>{status.migrations_pending.length} mise(s) à jour en attente</b>
					{:else}<b class="ok">à jour</b> ({status.migrations_applied} migrations){/if}
				</li>
				<li>Catalogue : <b>{status.risks}</b> risques publiés</li>
				<li>Administrateurs : <b>{status.admins}</b></li>
			</ul>
			<div class="owner">
				<p class="muted small">
					Utilisateur de la base qui a <b>tous les droits</b> (Manager &gt; Bases de données). Il sert uniquement à
					créer ou mettre à jour les tables, pour cette opération : il n'est <b>jamais enregistré</b>, ni dans
					<code>.env</code> ni dans les journaux.
				</p>
				<label>Utilisateur administrateur de la base <input type="text" autocomplete="off" bind:value={owner.user} /></label>
				{#if fields.db_admin_user}<p class="err">{fields.db_admin_user}</p>{/if}
				<label>Mot de passe <input type="password" autocomplete="off" bind:value={owner.password} /></label>
			</div>
			<button onclick={install} disabled={busy || !owner.user || !owner.password}>
				{status.installed ? 'Mettre à jour la base et le catalogue' : 'Installer la base et le catalogue'}
			</button>
			{#if log.length}<pre>{log.join('\n')}</pre>{/if}
		</section>

		{#if status.installed && status.admins === 0 && !totp}
			<section class="card">
				<h2>3. Premier administrateur</h2>
				<form onsubmit={createAdmin}>
					<label>E-mail <input type="email" autocomplete="username" bind:value={admin.email} /></label>
					{#if fields.email}<p class="err">{fields.email}</p>{/if}
					<label>Nom affiché <input type="text" bind:value={admin.name} /></label>
					{#if fields.name}<p class="err">{fields.name}</p>{/if}
					<label>Mot de passe (14 caractères minimum) <input type="password" autocomplete="new-password" bind:value={admin.password} /></label>
					{#if fields.password}<p class="err">{fields.password}</p>{/if}
					<button type="submit" disabled={busy}>Créer le compte</button>
				</form>
			</section>
		{/if}

		{#if totp}
			<section class="card highlight">
				<h2>4. Application d'authentification</h2>
				<p><b>Scannez ce QR code</b> avec votre application d'authentification (Microsoft ou Google Authenticator, 2FAS, Aegis, Mots de passe d'iOS). Il ne sera plus affiché.</p>
				<div class="qr" aria-label="QR code de la clé d'authentification">{@html totp.qr}</div>
				<p class="muted small">Sur le téléphone qui affiche cette page : <a href={totp.uri}>ouvrir directement dans l'application</a>. Ou saisie manuelle de la clé (type : basé sur le temps) :</p>
				<p class="secret">{totp.secret.match(/.{1,4}/g)?.join(' ')}</p>
				<div class="probe">
					<label>Pour vérifier, tapez le code à 6 chiffres que l'application affiche maintenant
						<span class="row"><input type="text" inputmode="numeric" maxlength="7" bind:value={probe} /><button onclick={checkProbe} disabled={probe.replace(/\s/g, '').length !== 6}>Vérifier</button></span>
					</label>
					{#if probeResult === 'ok'}<p class="ok">✅ C'est bon : l'application est bien configurée. Vous pouvez vous connecter.</p>
					{:else if probeResult === 'ko'}<p class="err">✕ Ce code ne correspond pas. Vérifiez que l'heure du téléphone est automatique, ou rescannez le QR code.</p>{/if}
				</div>
			</section>
		{/if}

		{#if status.installed && status.admins > 0 && !totp}
			<section class="card">
				<h2>Réinitialiser l'authentification</h2>
				<p class="muted small">
					Code refusé, clé perdue, nouveau téléphone ? Donnez l'e-mail et le mot de passe du compte : une nouvelle clé est
					générée (l'ancienne cesse de fonctionner) et un éventuel blocage après trop d'essais est levé.
				</p>
				<form onsubmit={resetTotp}>
					<label>E-mail <input type="email" autocomplete="username" bind:value={reset.email} /></label>
					<label>Mot de passe <input type="password" autocomplete="current-password" bind:value={reset.password} /></label>
					<button type="submit" disabled={busy || !reset.email || !reset.password}>Générer une nouvelle clé</button>
				</form>
			</section>
		{/if}

		{#if status.installed && status.admins > 0}
			<section class="card done">
				<h2>✅ Terminé</h2>
				<ol>
					<li>Retirez la ligne <code>SETUP_TOKEN=...</code> du fichier <code>.env</code> et renvoyez-le par FTP.</li>
					<li>Connectez-vous sur <a href="/admin/">/admin/</a>.</li>
					<li>Créez la tâche planifiée du collecteur dans le Manager Infomaniak (voir INSTALLATION.txt).</li>
				</ol>
			</section>
		{/if}
	{/if}
</div>

<style>
	.page {
		max-width: 680px;
		margin: 0 auto;
	}
	h1 {
		color: var(--primary);
		font-size: 22px;
	}
	.muted {
		color: var(--muted);
		font-size: 13px;
	}
	.small {
		font-size: 12px;
	}
	.card {
		background: var(--surface);
		border-radius: 12px;
		padding: 20px 22px;
		margin: 16px 0;
		box-shadow: var(--shadow-sm);
	}
	.card h2 {
		margin: 0 0 12px;
		font-size: 15px;
	}
	.qr {
		width: 220px;
		max-width: 100%;
		background: white;
		padding: 8px;
		border-radius: 8px;
		border: 1px solid var(--border);
		margin: 8px 0;
	}
	.qr :global(svg) {
		display: block;
		width: 100%;
		height: auto;
	}
	.probe {
		margin-top: 14px;
		padding-top: 12px;
		border-top: 1px solid var(--border);
	}
	.probe .row {
		margin-top: 6px;
	}
	.owner {
		margin: 12px 0;
		padding: 12px 14px;
		background: #f8fafc;
		border-radius: 8px;
	}
	.highlight {
		border: 2px solid var(--leaks);
	}
	.done {
		border: 2px solid var(--ok);
	}
	.row {
		display: flex;
		gap: 10px;
	}
	input {
		flex: 1;
		width: 100%;
		padding: 10px 12px;
		border: 1px solid var(--border);
		border-radius: 8px;
		font-family: inherit;
		font-size: 14px;
		margin-top: 4px;
	}
	label {
		display: block;
		font-size: 13px;
		font-weight: 600;
		margin-bottom: 10px;
	}
	button {
		background: var(--primary);
		color: white;
		border: none;
		border-radius: 8px;
		padding: 10px 16px;
		font-weight: bold;
		font-family: inherit;
		cursor: pointer;
	}
	button:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	ul,
	ol {
		font-size: 14px;
		line-height: 1.8;
		padding-left: 20px;
	}
	.ok {
		color: #059669;
	}
	.err {
		color: #dc2626;
		font-size: 12px;
		margin: -6px 0 10px;
	}
	pre {
		background: #0f172a;
		color: #e2e8f0;
		padding: 12px;
		border-radius: 8px;
		font-size: 12px;
		overflow-x: auto;
		margin-top: 12px;
	}
	.secret {
		font-family: ui-monospace, monospace;
		font-size: 20px;
		letter-spacing: 1px;
		font-weight: bold;
		word-break: break-all;
	}
</style>
