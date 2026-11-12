<script lang="ts">
	import Modal from './Modal.svelte';

	let { open = $bindable(false) }: { open: boolean } = $props();
</script>

<Modal bind:open title="📋 Changelog">
	<h3>v5.0 : refonte complète <span class="date">2026</span></h3>
	<p>
		Reconstruction de zéro, en gardant le visuel et les fonctionnalités. <strong>Plus aucune IA</strong> : la
		veille repose sur des sources structurées et des règles traçables. Hébergement européen (PHP et MariaDB),
		aucun service tiers côté navigateur, Content Security Policy stricte. Catalogue revu : mappings ISO/IEC
		27001:2022 corrigés, ajout de CyFun 2023, NIST CSF 2.0 et CRA, table de correspondance entre
		référentiels. Filtres partageables par lien.
	</p>

	<h3>v4.3 : CRA et alertes temps réel <span class="date">Mars 2026</span></h3>
	<p>
		Ajout du référentiel Cyber Resilience Act. Alertes cyber en temps réel et notifications navigateur pour les
		alertes critiques. Durcissement des en-têtes de sécurité.
	</p>

	<h3>v4.2 : Data Leaks <span class="date">Mars 2026</span></h3>
	<p>Module dédié aux violations de données : organisation, données exposées, nombre de records.</p>

	<h3>v4.1 : veille cyber <span class="date">Mars 2026</span></h3>
	<p>Introduction du mode Cyberrisques, alimenté par une dizaine de sources spécialisées.</p>

	<h3>v4.0 : automatisation de l'ingestion <span class="date">Février 2026</span></h3>
	<p>Architecture serverless, ingestion automatique et interface d'administration avec validation.</p>

	<h3>v3.0 : catalogue collaboratif <span class="date">Janvier 2026</span></h3>
	<p>
		Formulaire de proposition communautaire avec validation éditoriale. Mapping ISO/IEC 27001:2022, NIS2 et
		DORA. Export Excel.
	</p>

	<h3>v2.0 : base de données structurée <span class="date">Décembre 2025</span></h3>
	<p>Passage à une base de données, filtres IT/OT, catégorie et impact, tableau de bord.</p>

	<h3>v1.0 : catalogue GRC statique <span class="date">Novembre 2025</span></h3>
	<p>Première version : un catalogue de risques structurés, avec scénario, mesures, impact et référentiels.</p>

	{#snippet footer()}
		<span>Construit par <strong>One Circle IT Solutions</strong></span>
		<span>v5.0</span>
	{/snippet}
</Modal>
