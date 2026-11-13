<script lang="ts">
	import { ApiError } from '#lib/api.js';

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
	let fields = $state<Record<string, string>>({});
	let totp = $state<{ secret: string; uri: string } | null>(null);

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
			log = (await call<{ log: string[] }>('POST', '/install', {})).log;
			status = await call<Status>('GET', '/status');
		});
	const createAdmin = (event: SubmitEvent) => {
		event.preventDefault();
		return run(async () => {
			fields = {};
			const r = await call<{ totp_secret: string; totp_uri: string }>('POST', '/admin', admin);
			totp = { secret: r.totp_secret, uri: r.totp_uri };
			admin.password = '';
			status = await call<Status>('GET', '/status');
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
			<button onclick={install} disabled={busy}>
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
				<h2>4. Code d'authentification</h2>
				<p>Ajoutez cette clé dans votre application d'authentification (Aegis, 2FAS, Microsoft ou Google Authenticator...). <b>Elle ne sera plus affichée.</b></p>
				<p class="secret">{totp.secret.match(/.{1,4}/g)?.join(' ')}</p>
				<p><a href={totp.uri}>Ouvrir dans l'application d'authentification</a> (depuis le téléphone)</p>
				<p class="muted small">Type : basé sur le temps, 6 chiffres, 30 secondes.</p>
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
