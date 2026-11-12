<script lang="ts">
	import { ApiError } from '#lib/api.js';
	import { adminApi, type Admin } from '#lib/admin-api.js';

	let { onlogin }: { onlogin: (admin: Admin) => void } = $props();

	let email = $state('');
	let password = $state('');
	let code = $state('');
	let error = $state<string | null>(null);
	let sending = $state(false);

	async function submit(event: SubmitEvent): Promise<void> {
		event.preventDefault();
		sending = true;
		error = null;
		try {
			onlogin(await adminApi.login(email, password, code));
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Impossible de joindre l’API.';
			code = '';
		} finally {
			sending = false;
			password = '';
		}
	}
</script>

<div class="login-screen">
	<form class="login-card" onsubmit={submit}>
		<h1>🛡️ Risk Studio</h1>
		<p>Administration. Mot de passe et code d'authentification requis.</p>
		<div class="field">
			<label for="email">E-mail</label>
			<input id="email" type="email" autocomplete="username" required bind:value={email} />
		</div>
		<div class="field">
			<label for="password">Mot de passe</label>
			<input id="password" type="password" autocomplete="current-password" required bind:value={password} />
		</div>
		<div class="field">
			<label for="code">Code à 6 chiffres</label>
			<input
				id="code"
				type="text"
				inputmode="numeric"
				autocomplete="one-time-code"
				pattern={'[0-9 ]{6,7}'}
				maxlength="7"
				required
				bind:value={code}
			/>
		</div>
		<button class="btn-login" type="submit" disabled={sending}>{sending ? 'Vérification...' : 'Se connecter'}</button>
		{#if error}<div class="login-error" role="alert">{error}</div>{/if}
	</form>
</div>

<style>
	.login-screen {
		display: flex;
		align-items: center;
		justify-content: center;
		min-height: 100vh;
		padding: 20px;
	}
	.login-card {
		background: var(--a-surface);
		border: 1px solid var(--a-border);
		border-radius: 16px;
		padding: 40px;
		width: 100%;
		max-width: 380px;
		box-shadow: 0 25px 50px rgba(0, 0, 0, 0.4);
	}
	h1 {
		font-size: 20px;
		color: var(--primary);
		margin: 0 0 6px;
	}
	p {
		font-size: 13px;
		color: var(--a-muted);
		margin: 0 0 28px;
	}
	.field {
		margin-bottom: 16px;
	}
	label {
		display: block;
		font-size: 12px;
		color: var(--a-muted);
		margin-bottom: 6px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.5px;
	}
	input {
		width: 100%;
		padding: 11px 14px;
		background: var(--a-surface2);
		border: 1px solid var(--a-border);
		border-radius: 8px;
		color: var(--a-text);
		font-size: 14px;
		font-family: inherit;
	}
	input:focus {
		border-color: var(--primary);
		outline: none;
	}
	.btn-login {
		width: 100%;
		padding: 12px;
		background: var(--primary);
		color: white;
		border: none;
		border-radius: 8px;
		font-size: 14px;
		font-weight: bold;
		cursor: pointer;
		margin-top: 8px;
		font-family: inherit;
	}
	.btn-login:disabled {
		opacity: 0.6;
	}
	.login-error {
		color: var(--a-error);
		font-size: 12px;
		margin-top: 12px;
	}
</style>
