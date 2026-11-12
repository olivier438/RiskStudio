<script lang="ts">
	import { onMount } from 'svelte';
	import { api, ApiError, type Reference } from '#lib/api.js';

	let reference = $state<Reference | null>(null);
	let kind = $state<'risk' | 'correction'>('risk');
	let sending = $state(false);
	let done = $state(false);
	let error = $state<string | null>(null);
	let fields = $state<Record<string, string>>({});

	let risk = $state({
		title: '',
		category: '',
		threat: '',
		scenario: '',
		measures: '',
		impact: 3,
		c: false,
		i: false,
		a: false,
		environment: 'IT' as 'IT' | 'OT' | 'BOTH',
		sectors: [] as string[],
		references: ''
	});
	let correction = $state({ risk_code: '', message: '' });
	let name = $state('');
	let email = $state('');
	let consent = $state(false);
	let website = $state('');

	onMount(async () => {
		reference = await api.reference().catch(() => null);
		const code = new URL(window.location.href).searchParams.get('corriger');
		if (code && /^R-[A-Z]{2,4}-\d{2,}$/.test(code)) {
			kind = 'correction';
			correction.risk_code = code;
		}
	});

	async function submit(event: SubmitEvent): Promise<void> {
		event.preventDefault();
		sending = true;
		error = null;
		fields = {};
		try {
			await api.propose({
				kind,
				payload:
					kind === 'risk'
						? {
								title: risk.title,
								category: risk.category,
								threat: risk.threat,
								scenario: risk.scenario,
								measures: risk.measures,
								impact: Number(risk.impact),
								cia: (risk.c ? 'C' : '') + (risk.i ? 'I' : '') + (risk.a ? 'A' : ''),
								environment: risk.environment,
								sectors: risk.sectors,
								references: risk.references
							}
						: { risk_code: correction.risk_code.trim().toUpperCase(), message: correction.message },
				submitter_name: name || undefined,
				submitter_email: email || undefined,
				consent,
				website
			});
			done = true;
			window.scrollTo({ top: 0, behavior: 'smooth' });
		} catch (e) {
			if (e instanceof ApiError) {
				error = e.message;
				fields = e.fields;
			} else {
				error = 'Impossible de joindre Risk Studio. Réessayez dans un instant.';
			}
		} finally {
			sending = false;
		}
	}
</script>

<svelte:head>
	<title>Risk Studio | Proposer un risque</title>
	<meta name="description" content="Proposez un nouveau risque ou une correction au catalogue Risk Studio." />
</svelte:head>

<div class="page">
	<header class="page-header">
		<a href="/" class="back-link">← Retour au catalogue</a>
		<div>
			<h1>➕ Proposer un risque</h1>
			<div class="subtitle">Chaque proposition est relue avant publication.</div>
		</div>
	</header>

	{#if done}
		<div class="form-card success" role="status">
			<h2>Merci !</h2>
			<p>
				Votre proposition est bien arrivée. Elle sera relue par l'équipe éditoriale avant toute publication.
				{#if email}Nous vous écrirons si une précision est nécessaire.{/if}
			</p>
			<a class="btn btn-pdf" href="/">Retour au catalogue</a>
		</div>
	{:else}
		<form onsubmit={submit} novalidate>
			<div class="form-card">
				<div class="kind" role="radiogroup" aria-label="Type de proposition">
					<label class:active={kind === 'risk'}>
						<input type="radio" name="kind" value="risk" bind:group={kind} /> Nouveau risque
					</label>
					<label class:active={kind === 'correction'}>
						<input type="radio" name="kind" value="correction" bind:group={kind} /> Correction d'un risque existant
					</label>
				</div>
			</div>

			{#if kind === 'risk'}
				<div class="form-card">
					<h2>Le risque</h2>
					<div class="form-group">
						<label for="title">Titre <span class="required">*</span></label>
						<input id="title" type="text" maxlength="255" bind:value={risk.title} aria-invalid={!!fields.title} />
						{#if fields.title}<div class="field-error">{fields.title}</div>{/if}
					</div>
					<div class="form-row">
						<div class="form-group">
							<label for="category">Catégorie <span class="required">*</span></label>
							<select id="category" bind:value={risk.category} aria-invalid={!!fields.category}>
								<option value="">Choisir...</option>
								{#each reference?.categories ?? [] as c (c.code)}<option value={c.code}>{c.name_fr}</option>{/each}
							</select>
							{#if fields.category}<div class="field-error">{fields.category}</div>{/if}
						</div>
						<div class="form-group">
							<label for="threat">Menace <span class="required">*</span></label>
							<input id="threat" type="text" maxlength="255" placeholder="Ex. : Accès non autorisé" bind:value={risk.threat} />
							{#if fields.threat}<div class="field-error">{fields.threat}</div>{/if}
						</div>
					</div>
					<div class="form-group">
						<label for="scenario">Scénario <span class="required">*</span></label>
						<textarea id="scenario" maxlength="2000" placeholder="Comment le risque se matérialise, concrètement." bind:value={risk.scenario}></textarea>
						{#if fields.scenario}<div class="field-error">{fields.scenario}</div>{/if}
					</div>
					<div class="form-group">
						<label for="measures">Mesures <span class="required">*</span></label>
						<textarea id="measures" maxlength="2000" placeholder="Ce qui réduit le risque." bind:value={risk.measures}></textarea>
						{#if fields.measures}<div class="field-error">{fields.measures}</div>{/if}
					</div>
				</div>

				<div class="form-card">
					<h2>Évaluation</h2>
					<div class="form-row">
						<div class="form-group">
							<label for="impact">Impact (1 à 5) <span class="required">*</span></label>
							<select id="impact" bind:value={risk.impact}>
								{#each [1, 2, 3, 4, 5] as n (n)}<option value={n}>{n}</option>{/each}
							</select>
						</div>
						<div class="form-group">
							<label for="environment">Environnement</label>
							<select id="environment" bind:value={risk.environment}>
								<option value="IT">IT</option>
								<option value="OT">OT</option>
								<option value="BOTH">IT et OT</option>
							</select>
						</div>
					</div>
					<fieldset class="form-group">
						<legend>Critères touchés <span class="required">*</span></legend>
						<label class="inline"><input type="checkbox" bind:checked={risk.c} /> Confidentiality</label>
						<label class="inline"><input type="checkbox" bind:checked={risk.i} /> Integrity</label>
						<label class="inline"><input type="checkbox" bind:checked={risk.a} /> Availability</label>
						{#if fields.cia}<div class="field-error">{fields.cia}</div>{/if}
					</fieldset>
					<div class="form-group">
						<label for="sectors">Secteurs <span class="optional">aucun = tous les secteurs</span></label>
						<select id="sectors" multiple size="6" bind:value={risk.sectors}>
							{#each reference?.sectors ?? [] as s (s.code)}<option value={s.code}>{s.name_fr}</option>{/each}
						</select>
						{#if fields.sectors}<div class="field-error">{fields.sectors}</div>{/if}
					</div>
					<div class="form-group">
						<label for="refs">Références suggérées <span class="optional">facultatif</span></label>
						<input id="refs" type="text" maxlength="500" placeholder="Ex. : ISO 27001 A.8.20, NIS2 Art. 21.2.e" bind:value={risk.references} />
						{#if fields.references}<div class="field-error">{fields.references}</div>{/if}
					</div>
				</div>
			{:else}
				<div class="form-card">
					<h2>La correction</h2>
					<div class="form-group">
						<label for="code">Code du risque <span class="required">*</span></label>
						<input id="code" type="text" maxlength="16" placeholder="Ex. : R-GOV-01" bind:value={correction.risk_code} />
						{#if fields.risk_code}<div class="field-error">{fields.risk_code}</div>{/if}
					</div>
					<div class="form-group">
						<label for="message">Ce qu'il faudrait corriger <span class="required">*</span></label>
						<textarea id="message" maxlength="2000" bind:value={correction.message}></textarea>
						{#if fields.message}<div class="field-error">{fields.message}</div>{/if}
					</div>
				</div>
			{/if}

			<div class="form-card">
				<h2>Vous <span class="optional">facultatif</span></h2>
				<div class="form-row">
					<div class="form-group">
						<label for="name">Nom ou pseudonyme</label>
						<input id="name" type="text" maxlength="100" autocomplete="name" bind:value={name} />
						{#if fields.submitter_name}<div class="field-error">{fields.submitter_name}</div>{/if}
					</div>
					<div class="form-group">
						<label for="email">E-mail</label>
						<input id="email" type="email" maxlength="254" autocomplete="email" bind:value={email} />
						{#if fields.submitter_email}<div class="field-error">{fields.submitter_email}</div>{/if}
					</div>
				</div>
				{#if email}
					<label class="inline consent">
						<input type="checkbox" bind:checked={consent} />
						J'accepte que mon adresse soit conservée pour échanger sur cette proposition. Elle n'est jamais publiée
						ni partagée, et elle est supprimée sur simple demande.
					</label>
					{#if fields.consent}<div class="field-error">{fields.consent}</div>{/if}
				{/if}
				<!-- Honeypot: hidden from people and assistive technologies. -->
				<div class="hp" aria-hidden="true">
					<label for="website">Ne pas remplir</label>
					<input id="website" type="text" tabindex="-1" autocomplete="off" bind:value={website} />
				</div>
			</div>

			{#if error}<div class="error-msg" role="alert">{error}</div>{/if}
			<button class="btn btn-pdf submit" type="submit" disabled={sending}>
				{sending ? 'Envoi...' : 'Envoyer la proposition'}
			</button>
		</form>
	{/if}
</div>

<style>
	.page {
		max-width: 720px;
		margin: 0 auto;
	}
	.page-header {
		display: flex;
		align-items: center;
		gap: 16px;
		margin-bottom: 30px;
		padding-bottom: 20px;
		border-bottom: 2px solid var(--border);
		flex-wrap: wrap;
	}
	.back-link {
		color: var(--primary);
		text-decoration: none;
		font-size: 13px;
		font-weight: 600;
	}
	h1 {
		margin: 0;
		font-size: 22px;
		color: var(--primary);
	}
	.subtitle {
		font-size: 13px;
		color: var(--muted);
		margin-top: 4px;
	}
	.form-card {
		background: var(--surface);
		border-radius: 14px;
		padding: 28px;
		box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
		margin-bottom: 20px;
	}
	.form-card h2 {
		margin: 0 0 20px;
		font-size: 14px;
		text-transform: uppercase;
		letter-spacing: 0.5px;
		color: var(--muted);
	}
	.success h2 {
		color: #059669;
	}
	.form-group {
		margin-bottom: 18px;
		border: none;
		padding: 0;
	}
	label,
	legend {
		display: block;
		font-size: 13px;
		font-weight: 600;
		color: #374151;
		margin-bottom: 6px;
	}
	.required {
		color: #dc2626;
		margin-left: 3px;
	}
	.optional {
		color: #94a3b8;
		font-weight: normal;
		font-size: 11px;
		margin-left: 6px;
		text-transform: none;
		letter-spacing: 0;
	}
	input[type='text'],
	input[type='email'],
	textarea,
	select {
		width: 100%;
		padding: 10px 12px;
		border: 1px solid var(--border);
		border-radius: 8px;
		font-size: 13px;
		font-family: inherit;
		background: #fafafa;
		color: var(--text);
	}
	input:focus,
	textarea:focus,
	select:focus {
		border-color: var(--primary);
		box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
		background: white;
		outline: none;
	}
	[aria-invalid='true'] {
		border-color: #dc2626;
	}
	textarea {
		resize: vertical;
		min-height: 90px;
	}
	.form-row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 16px;
	}
	.inline {
		display: flex;
		gap: 8px;
		align-items: flex-start;
		font-weight: normal;
	}
	.consent {
		font-size: 12px;
		color: var(--muted-strong);
	}
	.field-error {
		color: #dc2626;
		font-size: 12px;
		margin-top: 4px;
	}
	.kind {
		display: flex;
		gap: 10px;
		flex-wrap: wrap;
	}
	.kind label {
		border: 1px solid var(--border);
		border-radius: 8px;
		padding: 10px 14px;
		cursor: pointer;
		display: flex;
		gap: 8px;
		align-items: center;
		margin: 0;
	}
	.kind label.active {
		border-color: var(--primary);
		background: #eff6ff;
	}
	.hp {
		position: absolute;
		left: -10000px;
		width: 1px;
		height: 1px;
		overflow: hidden;
	}
	.submit {
		width: 100%;
		justify-content: center;
		padding: 14px;
		font-size: 14px;
	}
	@media (max-width: 640px) {
		.form-row {
			grid-template-columns: 1fr;
		}
		.form-card {
			padding: 20px;
		}
	}
</style>
