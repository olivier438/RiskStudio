<script lang="ts">
	type Status = 'done' | 'partial' | 'todo';

	// Self-assessment of Risk Studio v5 itself against Regulation (EU) 2024/2847.
	// Keep it honest: update a line when the code changes.
	const CHECKS: { ref: string; label: string; how: string; status: Status }[] = [
		{ ref: 'Annexe I, I.2.b', label: 'Sécurisé par défaut', how: 'Aucun identifiant par défaut : les comptes admin se créent en ligne de commande, mot de passe de 14 caractères minimum.', status: 'done' },
		{ ref: 'Annexe I, I.2.d', label: 'Protection contre les accès non autorisés', how: 'Mot de passe argon2id + TOTP obligatoire, sessions en base (jeton haché), CSRF, frein aux tentatives, utilisateurs MariaDB à moindre privilège.', status: 'done' },
		{ ref: 'Annexe I, I.2.e', label: 'Confidentialité des données', how: 'HTTPS et HSTS, aucune IP stockée en clair (HMAC), e-mail des contributeurs facultatif et jamais publié.', status: 'done' },
		{ ref: 'Annexe I, I.2.f', label: 'Intégrité des données et des commandes', how: 'Validation éditoriale, vues publiques en lecture seule, CSP stricte sans unsafe-inline, journal d’audit.', status: 'done' },
		{ ref: 'Annexe I, I.2.h', label: 'Disponibilité des fonctions essentielles', how: 'Limitation de débit sur les écritures publiques, polling par ETag, collecteur isolé par source.', status: 'done' },
		{ ref: 'Annexe I, I.2.j', label: 'Surface d’attaque limitée', how: 'Aucun CDN, aucun script tiers, aucune police externe ; API minimale, une seule route publique en écriture.', status: 'done' },
		{ ref: 'Annexe I, I.2.l', label: 'Journalisation de l’activité', how: 'Journal d’audit des décisions et connexions, journal des passages du collecteur.', status: 'done' },
		{ ref: 'Annexe I, I.2.a', label: 'Pas de vulnérabilité exploitable connue', how: 'Lockfiles, composer audit et npm audit en CI, mises à jour Dependabot chaque semaine.', status: 'done' },
		{ ref: 'Annexe I, II.1', label: 'SBOM', how: 'SBOM CycloneDX généré en CI et livré avec chaque release (scripts/sbom.sh, dossier sbom/ de l’application).', status: 'done' },
		{ ref: 'Annexe I, II.5', label: 'Politique de divulgation coordonnée', how: 'SECURITY.md v3 (délais de correction, embargo) et /.well-known/security.txt (RFC 9116).', status: 'done' },
		{ ref: 'Art. 14', label: 'Processus de signalement', how: 'Délais et canal (plateforme ENISA, CCB) documentés dans SECURITY.md ; exercice de notification à planifier.', status: 'partial' }
	];

	const ICON: Record<Status, string> = { done: '✅', partial: '🟡', todo: '⬜' };
	const done = CHECKS.filter((c) => c.status === 'done').length;
</script>

<section class="intro">
	<h2>🔒 Cyber Resilience Act (Règlement UE 2024/2847)</h2>
	<p>
		Auto-évaluation de Risk Studio lui-même. Les obligations de signalement de l'Art. 14 s'appliquent depuis le
		<b>11 septembre 2026</b>, l'ensemble du règlement à partir du <b>11 décembre 2027</b>. Un logiciel libre fourni
		hors activité commerciale peut sortir du champ : la grille reste une bonne pratique.
	</p>
	<p class="score">{done} exigences sur {CHECKS.length} couvertes</p>
</section>

<table class="a-table">
	<thead><tr><th></th><th>Référence</th><th>Exigence</th><th>Mise en œuvre</th></tr></thead>
	<tbody>
		{#each CHECKS as c (c.ref)}
			<tr>
				<td>{ICON[c.status]}</td>
				<td class="nowrap"><code>{c.ref}</code></td>
				<td><b>{c.label}</b></td>
				<td class="how">{c.how}</td>
			</tr>
		{/each}
	</tbody>
</table>

<section class="deadlines">
	<h3>Délais de signalement (Art. 14)</h3>
	<div class="cols">
		<div>
			<h4>Vulnérabilité activement exploitée</h4>
			<ol>
				<li><b>24 h</b> : alerte précoce</li>
				<li><b>72 h</b> : notification de la vulnérabilité</li>
				<li><b>14 jours</b> après la mise à disposition d'un correctif : rapport final</li>
			</ol>
		</div>
		<div>
			<h4>Incident grave affectant la sécurité</h4>
			<ol>
				<li><b>24 h</b> : alerte précoce</li>
				<li><b>72 h</b> : notification de l'incident</li>
				<li><b>1 mois</b> : rapport final</li>
			</ol>
		</div>
	</div>
	<p class="a-muted">
		Notification via la plateforme unique de signalement de l'ENISA, au CSIRT coordinateur : en Belgique, le CCB.
	</p>
</section>

<style>
	.intro h2 {
		font-size: 16px;
		margin: 0 0 8px;
	}
	.intro p {
		font-size: 13px;
		line-height: 1.6;
		margin: 0 0 8px;
		max-width: 860px;
	}
	.score {
		font-weight: bold;
		color: var(--a-success);
	}
	.nowrap {
		white-space: nowrap;
	}
	.how {
		font-size: 12px;
		color: var(--a-muted);
	}
	.deadlines {
		background: var(--a-surface);
		border: 1px solid var(--a-border);
		border-radius: 12px;
		padding: 16px 18px;
		margin-top: 18px;
	}
	.deadlines h3 {
		margin: 0 0 12px;
		font-size: 14px;
	}
	.cols {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
		gap: 16px;
	}
	h4 {
		margin: 0 0 6px;
		font-size: 13px;
		color: var(--a-warning);
	}
	ol {
		margin: 0;
		padding-left: 18px;
		font-size: 13px;
		line-height: 1.7;
	}
	.deadlines p {
		font-size: 12px;
		margin: 12px 0 0;
	}
</style>
