<script lang="ts">
	import Modal from './Modal.svelte';

	let { open = $bindable(false) }: { open: boolean } = $props();
</script>

<Modal bind:open title="🛡️ NOROSHI">
	<h3>Ce qu'est NOROSHI</h3>
	<p>
		NOROSHI réunit deux outils pour les professionnels de la cybersécurité : un <strong
			>catalogue de risques GRC</strong
		>, structuré et mappé sur les référentiels du terrain, et une <strong>veille cyber</strong> alimentée par
		des sources d'autorité. Gratuit, ouvert, sans abonnement.
	</p>

	<h3>Pourquoi on l'a construit</h3>
	<p>
		Chaque nouvelle mission repart de zéro. Les catalogues de risques sont soit verrouillés derrière des
		paywalls, soit trop génériques, soit périmés. NOROSHI est né d'une conviction simple : les
		professionnels GRC méritent un outil commun, aligné sur les vrais référentiels.
	</p>

	<h3>Comment ça fonctionne</h3>
	<ul>
		<li>🔍 <strong>Cherchez</strong> par mot-clé, menace, CVE, produit ou référence de contrôle</li>
		<li>🏷️ <strong>Filtrez</strong> par environnement IT / OT, secteur, catégorie, référentiel et impact</li>
		<li>☑️ <strong>Sélectionnez</strong> les éléments pertinents pour votre mission</li>
		<li>📊 <strong>Exportez</strong> en Excel (CSV) ou en PDF</li>
		<li>🔗 <strong>Partagez</strong> une vue filtrée : les filtres vivent dans l'adresse de la page</li>
	</ul>

	<h3>Une veille sans intelligence artificielle</h3>
	<p>
		NOROSHI n'utilise <strong>aucune IA</strong>. La veille s'appuie sur des sources déjà structurées
		(CISA KEV, NVD, FIRST EPSS, ENISA EUVD, CERT nationaux) et sur des <strong>règles explicites</strong> :
		correspondance CWE vers catégorie, produit vers environnement IT/OT, score calculé à partir du CVSS, de
		l'EPSS et de l'exploitation connue.
	</p>
	<p>
		Chaque élément conserve la liste des règles qui l'ont classé. Le bouton « Pourquoi ? » l'affiche : tout
		résultat est traçable et reproductible.
	</p>
	<ul>
		<li>🔥 <strong>Critique</strong> : exploitation connue (KEV) ou sévérité critique.</li>
		<li>
			📮 <strong>Publication</strong> : directe pour les sources d'autorité, après validation éditoriale pour
			les autres.
		</li>
	</ul>

	<h3>Référentiels couverts</h3>
	<div>
		<span class="modal-tag">ISO/IEC 27001:2022</span>
		<span class="modal-tag">NIS2</span>
		<span class="modal-tag">DORA</span>
		<span class="modal-tag">CRA (Règlement UE 2024/2847)</span>
		<span class="modal-tag">CyFun 2023</span>
		<span class="modal-tag">NIST CSF 2.0</span>
	</div>
	<p class="note">
		Les mappings en italique gris sont <em>dérivés</em> d'un mapping ISO par la table de correspondance. Les
		autres sont éditoriaux.
	</p>

	<h3>Architecture</h3>
	<p>
		Frontend statique (SvelteKit), API PHP et base MariaDB, hébergés en Europe. Aucun CDN, aucun traceur,
		aucune police externe : votre navigateur ne parle qu'à NOROSHI. La base n'est jamais exposée : l'API
		publique ne lit que le contenu publié, avec un utilisateur en lecture seule.
	</p>

	{#snippet footer()}
		<span>Construit par <strong>One Circle IT Solutions</strong> · Licence CC BY-SA 4.0</span>
		<span>noroshi.be</span>
	{/snippet}
</Modal>

<style>
	.note {
		font-size: 12px;
		color: var(--muted);
		margin-top: 10px;
	}
</style>
