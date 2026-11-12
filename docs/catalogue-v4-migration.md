# Catalogue v4 → v5 : rapport de migration

Généré par `scripts/legacy/convert-v4-catalogue.php`. À relire et valider.

- Risques v4 : 168
- Risques v5 : 167
- Risques modifiés : 151

## Règles appliquées à tout le catalogue

- **DIC → CIA** : Disponibilité devient Availability (A), les lettres C et I restent.
- **Secteurs** : Finance devient Banking + Insurance, Secteur Public devient Public administration + Local government, Industrie devient Manufacturing, Technologie devient Digital providers + ICT service management. "Tous", "Développement" et "RH" deviennent transversaux (aucun secteur).
- **NIS2** : le texte libre v4 ("Hygiène informatique", "Gouvernance"...) est abandonné. Les articles NIS2 sont dérivés des contrôles ISO par la table de correspondance, plus quelques ajouts explicites.
- **CyFun 2023 et NIST CSF 2.0** : dérivés des contrôles ISO par la table de correspondance.
- **Termes** : RGPD devient GDPR, Azure AD devient Microsoft Entra ID.

## Détail par risque

### R-GOV-01 | Absence d'Information Security Policy

- CIA : D (DIC) → CIA
- ISO 27001 : 5.1 → 5.2, A.5.1
- Titre : « Absence de PSSI » → « Absence d'Information Security Policy »
- Mesures : « Rédiger et valider une PSSI. » → « Rédiger, faire approuver par la direction et diffuser une Information Security Policy. »

### R-GOV-02 | Absence de revue de direction

- ISO 27001 : 5.5 → 9.3, A.5.4
- NIS2 : « Gouvernance » → Art.20 (en plus des correspondances ISO)

### R-GOV-03 | Budget cyber insuffisant

- ISO 27001 : 5.1 → 7.1, 5.1
- NIS2 : « Gestion des risques » → Art.20 (en plus des correspondances ISO)

### R-ACC-01 | MFA non activé sur VPN

- ISO 27001 : A.9.2 → A.8.5, A.5.17
- NIS2 : « Contrôle d'accès » → Art.21.2.j (en plus des correspondances ISO)

### R-ACC-02 | Comptes administrateurs partagés

- ISO 27001 : A.8.2 → A.5.16, A.8.2

### R-ACC-03 | Droits excessifs (Shadow Admin)

- ISO 27001 : A.8.2 → A.5.15, A.5.18, A.8.3

### R-OPS-01 | Retard de correctifs critiques

- Catégorie : Opérations → VULN

### R-OPS-02 | Sauvegardes non testées

- Catégorie : Opérations → BCM
- ISO 27001 : A.8.14 → A.8.13

### R-OPS-03 | Absence de segmentation IT/OT

- Catégorie : Industrie, Énergie → OT
- Secteurs : Propagation malware → MANUFACTURING, ENERGY
- ISO 27001 : A.8.1 → A.8.22, A.8.20
- Menace : « Sinistre technique » → « Propagation de malware »
- Scénario : «  » → « Un malware introduit sur le réseau bureautique se propage jusqu'aux automates faute de cloisonnement entre IT et OT. »

### R-OPS-04 | Logs non centralisés

- ISO 27001 : A.8.15 → A.8.15, A.8.16

### R-SUP-01 | Faillite d'un prestataire Cloud

- ISO 27001 : A.5.21 → A.5.19, A.5.23, A.5.30

### R-SUP-02 | Accès tiers non supervisé

- ISO 27001 : A.5.22 → A.5.15, A.5.19, A.5.20

### R-RH-02 | Départ collaborateur non géré

- ISO 27001 : A.5.10 → A.6.5, A.5.11, A.5.18

### R-PHY-01 | Local serveur non sécurisé

- ISO 27001 : A.7.2 → A.7.1, A.7.2, A.7.3

### R-PHY-02 | Vol d'ordinateurs portables

- ISO 27001 : A.7.9 → A.7.9, A.8.1, A.8.24

### R-DEV-01 | Secrets en dur dans le code

- ISO 27001 : A.8.25 → A.8.4, A.8.25, A.8.28
- CRA : ajout AnnexI.I.1

### R-DAT-01 | Absence de classification

- ISO 27001 : A.8.11 → A.5.12, A.5.13

### R-BCP-01 | Disaster Recovery Plan non documenté

- ISO 27001 : A.5.30 → A.5.29, A.5.30
- Titre : « PRA non documenté » → « Disaster Recovery Plan non documenté »
- Mesures : « Rédiger un Plan de Reprise d'Activité détaillé. » → « Rédiger un Disaster Recovery Plan détaillé et le tester. »

### R-IT-21 | Shadow IT (SaaS non autorisé)

- ISO 27001 : A.8.1 → A.5.9, A.5.23

### R-IT-22 | Empoisonnement de modèle IA (Prompt Injection)

- Fusionné dans R-AIA-02 (doublon)

### R-IT-23 | Épuisement de ressources Cloud

- ISO 27001 : A.8.6 → A.8.6, A.5.23
- Scénario : « Une boucle infinie ou une attaque DDOS fait exploser la facture Cloud et coupe le service. » → « Une boucle infinie ou une attaque DDoS fait exploser la facture Cloud et coupe le service. »

### R-IT-24 | Compromission de la chaîne de build (CI/CD)

- ISO 27001 : A.8.25 → A.8.25, A.8.32, A.8.4, A.8.31
- DORA : Art. 15 → Art.9
- CRA : ajout AnnexI.I.2.f, AnnexI.II.7

### R-IT-25 | Secrets exposés dans les métadonnées

- Catégorie : Développement → DEV
- ISO 27001 : A.8.11 → A.8.4, A.8.9, A.8.25

### R-IT-26 | Usurpation d'identité via Deepfake

- ISO 27001 : 6.3 → A.6.3, A.5.37

### R-IT-27 | Défaut de nettoyage des assets cloud (Ghost assets)

- ISO 27001 : A.8.1 → A.5.9, A.8.10, A.5.23

### R-IT-28 | Attaque par 'Man-in-the-Middle' sur Wi-Fi invité

- Catégorie : Physique → INFRA
- ISO 27001 : A.8.20 → A.8.20, A.8.22

### R-IT-29 | Incapacité à restaurer (Backups chiffrés)

- Catégorie : Opérations → BCM
- ISO 27001 : A.8.14 → A.8.13

### R-IT-30 | Exfiltration de données via tunnels DNS

- ISO 27001 : A.8.20 → A.8.16, A.8.12

### R-OT-01 | Accès distant de maintenance non sécurisé

- ISO 27001 : A.5.22 → A.5.19, A.5.22, A.8.5

### R-OT-02 | Infection par média amovible (Clé USB de maintenance)

- ISO 27001 : A.7.9 → A.7.10, A.8.7

### R-OT-03 | Saturation du bus de terrain (DoS industriel)

- ISO 27001 : N/A → A.8.22, A.8.20, A.8.6

### R-OT-04 | Obsolescence des OS industriels (XP, Win7)

- Catégorie : OT → VULN
- ISO 27001 : A.8.8 → A.8.8, A.8.22

### R-OT-05 | Modification non autorisée de la logique automate

- ISO 27001 : A.8.1 → A.8.9, A.8.32, A.8.19

### R-OT-06 | Falsification de données de capteurs (Spoofing)

- ISO 27001 : N/A → A.8.16, A.8.20

### R-OT-07 | Défaut de redondance des réseaux de contrôle

- ISO 27001 : A.5.30 → A.8.14, A.8.20

### R-OT-08 | Accès physique aux ports RJ45 en atelier

- ISO 27001 : A.7.2 → A.7.2, A.8.20

### R-OT-09 | Absence de visibilité sur les assets OT

- ISO 27001 : A.8.1 → A.5.9

### R-OT-10 | Attaque par rebond IT vers OT

- ISO 27001 : A.8.20 → A.8.22, A.8.20
- Mesures : « Mise en œuvre d'une DMZ industrielle et pare-feu d'inspection profonde (DPI). » → « Mise en œuvre d'une DMZ industrielle et de pare-feu à inspection profonde (Deep Packet Inspection). »

### R-PHY-03 | Accès par 'Tailgating' (Talonnage)

- ISO 27001 : A.7.2 → A.7.2, A.6.3

### R-PHY-06 | Accès non surveillé aux zones de livraison

- ISO 27001 : A.7.3 → A.7.2, A.7.3

### R-PHY-08 | Inondation ou dégât des eaux

- ISO 27001 : A.7.5 → A.7.5, A.7.8

### R-PHY-09 | Vol de supports de sauvegarde hors site

- ISO 27001 : A.7.9 → A.7.9, A.7.10, A.8.24

### R-PHY-10 | Écrans visibles depuis l'extérieur (Visual Sniffing)

- ISO 27001 : A.7.1 → A.7.7, A.7.8

### R-PHY-11 | Documents sensibles laissés sur l'imprimante

- ISO 27001 : A.7.1 → A.7.7

### R-PHY-12 | Vandalisme sur terminaux publics (Bornes)

- ISO 27001 : A.7.9 → A.7.8

### R-PHY-13 | Panne de climatisation prolongée

- ISO 27001 : A.7.5 → A.7.11

### R-PHY-14 | Coupure fibre accidentelle (Travaux)

- ISO 27001 : N/A → A.7.12, A.8.14

### R-PHY-15 | Alimentation électrique instable (Surtension)

- ISO 27001 : A.7.5 → A.7.11

### R-PHY-16 | Accès aux ports console en libre-service

- ISO 27001 : A.8.20 → A.7.8, A.7.12, A.8.20

### R-PHY-17 | Espionnage via 'Shoulder Surfing'

- ISO 27001 : 6.3 → A.6.3, A.7.7

### R-PHY-18 | Infiltration par les faux-plafonds

- ISO 27001 : A.7.2 → A.7.1, A.7.3

### R-PHY-19 | Vol de composants internes (RAM/CPU)

- ISO 27001 : A.7.9 → A.7.8, A.7.2

### R-PHY-20 | Indisponibilité des systèmes de sécurité

- ISO 27001 : A.7.2 → A.7.4

### R-SUP-03 | Compromission du dépôt de code tiers (Open Source)

- ISO 27001 : A.8.28 → A.5.21, A.8.28
- CRA : ajout AnnexI.II.1

### R-SUP-04 | Rebond via outil de télémaintenance prestataire

- ISO 27001 : A.5.22 → A.5.19, A.5.22, A.8.5
- DORA : Art. 29 → Art.28
- Scénario : « Un pirate pirate le PC d'un technicien de maintenance et utilise son VPN actif pour entrer chez le client. » → « Un attaquant compromet le PC d'un technicien de maintenance et utilise son VPN actif pour entrer chez le client. »

### R-SUP-05 | Indisponibilité d'un fournisseur d'identité (IdP)

- ISO 27001 : A.8.2 → A.5.23, A.5.30, A.8.14
- Scénario : « Une panne majeure chez Microsoft Azure AD ou Okta empêche tous les employés de se connecter aux outils. » → « Une panne majeure chez Microsoft Entra ID ou Okta empêche tous les employés de se connecter aux outils. »

### R-SUP-06 | Modification malveillante du firmware à l'usine

- ISO 27001 : A.8.25 → A.5.21
- CRA : ajout AnnexI.I.2.f

### R-SUP-07 | Cessation d'activité soudaine du prestataire (Faillite)

- ISO 27001 : A.5.21 → A.5.19, A.5.20, A.5.30

### R-SUP-08 | Non-respect des SLA de sécurité par le tiers

- ISO 27001 : A.5.21 → A.5.22, A.5.20

### R-SUP-09 | Soumission de données à une IA publique

- ISO 27001 : A.8.12 → A.5.20, A.5.14

### R-SUP-10 | Changement de juridiction du Cloud (Cloud Act)

- ISO 27001 : A.5.37 → A.5.23, A.5.31, A.5.34

### R-SUP-11 | Défaut de sécurité du 'Dernier Kilomètre' (Logistique)

- ISO 27001 : A.7.9 → A.5.21, A.7.9

### R-SUP-12 | Vente de données par un partenaire commercial

- ISO 27001 : A.5.21 → A.5.20, A.5.34
- Menace : « Violation RGPD » → « Violation GDPR »

### R-SUP-13 | Sous-traitance en cascade non maîtrisée

- ISO 27001 : A.5.21 → A.5.21, A.5.20

### R-SUP-14 | Absence de correctifs sur matériel 'White Label'

- ISO 27001 : A.8.8 → A.5.21, A.8.8
- CRA : ajout Art.13, AnnexI.II.2

### R-SUP-15 | Outil de monitoring utilisé comme vecteur d'attaque

- ISO 27001 : A.8.15 → A.5.21, A.8.16

### R-SUP-16 | Rupture de stock de composants critiques

- ISO 27001 : N/A → A.5.30

### R-SUP-17 | Certificat SSL expiré chez un tiers

- ISO 27001 : A.8.24 → A.5.22, A.8.24

### R-SUP-18 | Fuite de données chez le cabinet comptable/RH

- ISO 27001 : A.5.21 → A.5.19, A.5.20, A.5.22

### R-SUP-19 | Malware pré-installé sur PC reconditionné

- ISO 27001 : A.7.9 → A.5.21, A.8.7

### R-SUP-20 | Portail support client compromis

- ISO 27001 : A.5.22 → A.5.22, A.8.7

### R-AIA-01 | Fuite de données via Prompt (Shadow AI)

- ISO 27001 : A.8.12 → A.5.10, A.8.12, A.5.23

### R-AIA-02 | Attaque par 'Prompt Injection'

- ISO 27001 : A.8.25 → A.8.25, A.8.26, A.8.28

### R-AIA-03 | Empoisonnement des données d'entraînement (Data Poisoning)

- ISO 27001 : N/A → A.8.25

### R-AIA-05 | Violation de copyright / Propriété Intellectuelle

- ISO 27001 : A.5.31 → A.5.32, A.5.31

### R-AIA-06 | Exfiltration du modèle (Model Inversion)

- ISO 27001 : A.8.1 → A.8.26

### R-AIA-07 | Biais algorithmiques et discrimination

- Secteurs : RH, Secteur Public → PUBLIC_ADMIN, LOCAL_GOV
- ISO 27001 : N/A → A.5.31

### R-AIA-08 | Dépendance critique à un fournisseur d'IA (Lock-in)

- ISO 27001 : A.5.21 → A.5.19, A.5.23, A.5.30

### R-AIA-11 | Non-conformité à l'EU AI Act

- ISO 27001 : N/A → A.5.31

### R-AIA-12 | Fuite de secrets via les logs d'IA

- ISO 27001 : A.8.15 → A.8.15, A.8.11

### R-AIA-14 | Shadow AI par détournement d'API

- ISO 27001 : A.8.2 → A.5.10, A.5.17

### R-AIA-15 | Deepfake utilisé pour contourner la biométrie

- ISO 27001 : A.9.2 → A.8.5

### R-AIA-17 | Manque de transparence (Boîte noire)

- ISO 27001 : N/A → A.5.31

### R-AIA-18 | Fuite de 'System Prompt'

- ISO 27001 : N/A → A.8.26, A.8.29

### R-AIA-19 | Infection via plugin/extension IA

- ISO 27001 : A.8.28 → A.5.21, A.8.7, A.8.19

### R-HOS-01 | Indisponibilité du Dossier Patient Informatisé

- Catégorie : Santé → BCM
- ISO 27001 : A.5.30 → A.5.29, A.5.30, A.8.13
- Titre : « Indisponibilité du Dossier Patient Informatisé (DPI) » → « Indisponibilité du Dossier Patient Informatisé »

### R-HOS-02 | Piratage de dispositif médical connecté (IoMT)

- Catégorie : Santé → INFRA
- ISO 27001 : A.8.20 → A.8.20, A.8.22
- Mesures : « Segmentation VLAN dédiée aux dispositifs médicaux (réseau ISO-MED). » → « Segmentation VLAN dédiée aux dispositifs médicaux connectés. »

### R-HOS-03 | Exfiltration de données de santé (Données Sensibles)

- ISO 27001 : A.8.11 → A.8.12, A.8.24, A.5.34
- Scénario : « La base de données des patients est revendue sur le Darkweb, violant gravement le RGPD. » → « La base de données des patients est revendue sur le Darkweb, violant gravement le GDPR. »

### R-HOS-04 | Accès illégitime au dossier d'une personnalité

- Catégorie : Santé → IAM
- ISO 27001 : A.8.2 → A.5.15, A.8.15, A.8.16

### R-HOS-05 | Interruption des systèmes de monitorage centralisé

- Catégorie : Santé → INFRA
- ISO 27001 : A.8.20 → A.8.14, A.8.20

### R-HOS-06 | Usurpation d'identité pour prescription

- Catégorie : Santé → IAM
- ISO 27001 : A.9.2 → A.8.5, A.7.7

### R-HOS-07 | Dysfonctionnement du système de transport pneumatique

- Catégorie : Santé → PHYS
- ISO 27001 : A.7.2 → A.7.11

### R-HOS-08 | Contamination par un prestataire de maintenance biomédicale

- ISO 27001 : A.5.22 → A.5.19, A.5.22, A.8.7

### R-HOS-09 | Perte de traçabilité des dispositifs stérilisés

- Catégorie : Santé → DATA
- ISO 27001 : N/A → A.5.33, A.8.13

### R-HOS-10 | Retard de mise à jour sur des équipements critiques (IRM/Scan)

- Catégorie : Santé → VULN
- ISO 27001 : A.8.8 → A.8.8, A.8.22

### R-HOS-11 | Panne du système d'appel malade

- ISO 27001 : A.7.5 → A.7.11, A.5.30

### R-HOS-12 | Détournement de la télémédecine (Vidéo-consultation)

- Catégorie : Santé → DATA
- ISO 27001 : A.5.37 → A.8.26, A.5.23, A.8.24
- Mesures : « Utilisation de solutions certifiées HDS (Hébergeur de Données de Santé). » → « Utilisation de solutions certifiées pour l'hébergement de données de santé et chiffrement de bout en bout. »

### R-HOS-13 | Saturation du réseau Wi-Fi par les patients

- Catégorie : Opérations → INFRA
- ISO 27001 : A.8.20 → A.8.20, A.8.22, A.8.6

### R-HOS-15 | Vol de serveurs ou de NAS dans des locaux isolés

- ISO 27001 : A.7.2 → A.7.2, A.8.24

### R-HOS-16 | Indisponibilité du système de gestion de la pharmacie

- Catégorie : Santé → BCM
- ISO 27001 : N/A → A.5.30

### R-HOS-17 | Exposition de données via la recherche clinique

- ISO 27001 : A.8.11 → A.8.11, A.5.34

### R-HOS-19 | Dépendance au Cloud pour des services vitaux

- ISO 27001 : A.5.21 → A.5.23, A.5.30

### R-HOS-20 | Sabotage du Building Management System (BMS)

- ISO 27001 : A.7.5 → A.7.11, A.8.22
- Titre : « Sabotage des systèmes de gestion technique (GTC/GTB) » → « Sabotage du Building Management System (BMS) »
- Mesures : « Isolation du réseau GTC du réseau IT et contrôle d'accès physique. » → « Isolation du réseau du Building Management System du réseau IT et contrôle d'accès physique. »

### R-LEG-01 | Non-conformité majeure au GDPR

- ISO 27001 : A.5.31 → A.5.31, A.5.34
- Titre : « Non-conformité majeure au RGPD » → « Non-conformité majeure au GDPR »
- Mesures : « Désignation d'un DPO et tenue du registre des traitements. » → « Désignation d'un Data Protection Officer et tenue du registre des traitements. »

### R-LEG-02 | Sanction pour non-respect de NIS2

- ISO 27001 : A.5.31 → A.5.31, A.5.36
- NIS2 : « Gouvernance » → Art.20 (en plus des correspondances ISO)
- Scénario : « L'autorité nationale (ANSSI) impose une amende record pour défaut de mesures de sécurité essentielles. » → « L'autorité nationale (le CCB en Belgique) impose une amende pour défaut de mesures de sécurité essentielles. »

### R-LEG-04 | Défaut de notification d'incident majeur

- ISO 27001 : A.5.24 → A.5.24, A.5.26, A.5.31
- NIS2 : « Gestion incidents » → Art.23 (en plus des correspondances ISO)
- Scénario : « L'entreprise cache une fuite de données et manque le délai légal de notification (72h). » → « L'entreprise cache un incident significatif et manque les délais légaux de notification (24h pour l'alerte précoce NIS2, 72h pour le GDPR). »

### R-LEG-05 | Nullité du contrat d'assurance Cyber

- ISO 27001 : A.5.21 → A.5.31, A.5.36

### R-LEG-06 | Contentieux avec un employé (Preuves numériques)

- ISO 27001 : A.8.15 → A.8.15, A.5.28

### R-LEG-07 | Violation de la souveraineté des données

- ISO 27001 : A.5.37 → A.5.23, A.5.31, A.5.34
- Mesures : « Hébergement sur Cloud Souverain (SecNumCloud). » → « Hébergement sur un Cloud souverain qualifié (SecNumCloud, EUCS) ou chiffrement avec gestion des clés par le client. »

### R-CRI-01 | Incapacité à communiquer en cas de crise

- ISO 27001 : A.5.30 → A.5.24, A.5.29

### R-CRI-02 | Saturation du service client (Panique)

- ISO 27001 : N/A → A.5.24, A.5.29

### R-CRI-03 | Décès ou incapacité d'un expert clé

- ISO 27001 : 6.1 → A.5.37

### R-CRI-04 | Espace de repli indisponible

- ISO 27001 : A.5.30 → A.5.29, A.5.30, A.6.7

### R-CRI-05 | Indisponibilité des numéros d'urgence prestataires

- ISO 27001 : A.5.21 → A.5.24, A.5.20

### R-HUM-02 | Ingénierie sociale par téléphone (Vishing)

- ISO 27001 : 6.3 → A.6.3, A.5.17

### R-HUM-03 | Sabotage par un administrateur mécontent

- ISO 27001 : A.5.10 → A.8.2, A.5.3, A.6.5

### R-HUM-04 | Utilisation du matériel pro à des fins illégales

- ISO 27001 : A.5.1 → A.5.10, A.6.4

### R-HUM-05 | Espionnage industriel par un stagiaire/prestataire

- ISO 27001 : A.5.10 → A.6.6, A.5.15

### R-TEC-01 | Algorithmes cryptographiques obsolètes

- Catégorie : Technique → INFRA
- Titre : « Collision de certificats cryptographiques » → « Algorithmes cryptographiques obsolètes »

### R-TEC-02 | Bruit électromagnétique (Tempest)

- Catégorie : Technique → PHYS
- ISO 27001 : A.7.1 → A.7.8

### R-TEC-03 | Défaut de synchronisation temporelle (NTP)

- Catégorie : Technique → OPS

### R-EXT-02 | Conflit armé ou instabilité géopolitique

- ISO 27001 : N/A → A.5.29, A.5.30

### R-EXT-03 | Pandémie ou crise sanitaire majeure

- ISO 27001 : N/A → A.5.29, A.5.30
- Mesures : « Plan de continuité d'activité (PCA) spécifique aux pandémies. » → « Business Continuity Plan spécifique aux pandémies. »

### R-EXT-04 | Catastrophe naturelle (Séisme, Tornade)

- ISO 27001 : A.7.5 → A.7.5, A.8.14, A.5.30

### R-EXT-05 | Activisme ou défaçage idéologique

- ISO 27001 : N/A → A.8.26, A.8.16

### R-LEG-08 | Inopposabilité des Conditions Générales (CGU)

- ISO 27001 : N/A → A.5.31

### R-LEG-09 | Requalification de sous-traitant en responsable conjoint

- ISO 27001 : N/A → A.5.34, A.5.20
- Mesures : « Convention de responsabilité conjointe (Art. 26 RGPD). » → « Convention de responsabilité conjointe (Art. 26 GDPR). »

### R-LEG-10 | Exportation illégale de technologies (EAR/ITAR)

- ISO 27001 : N/A → A.5.31

### R-CRI-06 | Erreur de manipulation durant le rétablissement

- ISO 27001 : A.5.30 → A.8.13, A.5.37

### R-TEC-04 | Dérive des horloges (Clock Drift) sur automates

- ISO 27001 : N/A → A.8.17

### R-HUM-06 | Accès indu par un "Pretexting" réussi

- ISO 27001 : 6.3 → A.6.3, A.7.2

### R-TEC-05 | Fragmentation excessive des logs (Data Silos)

- ISO 27001 : A.8.15 → A.8.15, A.8.16

### R-IAM-01 | Comptes orphelins (utilisateurs sortis)

- ISO 27001 : A.5.10 → A.5.18, A.6.5

### R-IAM-02 | Fatigue MFA (MFA Push Spamming)

- ISO 27001 : A.9.2 → A.8.5, A.6.3
- NIS2 : « Hygiène informatique » → Art.21.2.j (en plus des correspondances ISO)

### R-IAM-03 | Droits excessifs par héritage (Privilege Creep)

- ISO 27001 : A.8.2 → A.5.18

### R-IAM-04 | Utilisation de protocoles d'authentification obsolètes

- ISO 27001 : A.8.24 → A.8.5, A.8.24

### R-IAM-05 | Compte de service avec mot de passe statique

- ISO 27001 : A.8.2 → A.5.17, A.8.2

### R-IAM-06 | Accès administrateur sans MFA

- ISO 27001 : A.8.2 → A.8.2, A.8.5
- NIS2 : « Hygiène informatique » → Art.21.2.j (en plus des correspondances ISO)

### R-IAM-07 | Shadow IAM (Droits créés hors process)

- ISO 27001 : A.5.18 → A.8.2, A.5.18

### R-IAM-08 | Incohérence des identités entre On-premise et Cloud

- ISO 27001 : A.8.2 → A.5.16, A.5.18
- Mesures : « Monitoring des erreurs de synchronisation (Azure AD Connect, etc.). » → « Monitoring des erreurs de synchronisation (Microsoft Entra ID Connect, etc.). »

### R-IAM-09 | Clés d'API et jetons (Tokens) longue durée

- ISO 27001 : A.8.25 → A.5.17, A.8.5

### R-IAM-10 | Attaque de type 'Golden Ticket' (Kerberos)

- ISO 27001 : N/A → A.8.2, A.8.5, A.8.16

### R-IAM-12 | Comptes invités (B2B) non supervisés

- ISO 27001 : A.5.22 → A.5.18, A.5.19

### R-IAM-13 | Stockage des mots de passe en clair (Base de données)

- ISO 27001 : A.8.11 → A.8.24, A.5.17
- CRA : ajout AnnexI.I.2.e

### R-IAM-14 | Contournement de la biométrie (Photo/Masque)

- ISO 27001 : A.9.2 → A.8.5

### R-IAM-15 | Accès conditionnel mal configuré

- ISO 27001 : A.8.20 → A.5.15, A.8.5

### R-IAM-16 | Session persistante sur poste partagé

- ISO 27001 : A.7.2 → A.7.7, A.8.5

### R-IAM-17 | Usurpation d'identité par SMS Swapping

- ISO 27001 : 6.3 → A.8.5
- NIS2 : « Hygiène informatique » → Art.21.2.j (en plus des correspondances ISO)

### R-IAM-18 | Absence d'historique des changements de droits

- ISO 27001 : A.8.15 → A.8.15, A.5.18

### R-IAM-19 | Droits d'administration par défaut sur les postes

- ISO 27001 : A.8.2 → A.8.2, A.8.19

### R-IAM-20 | Défaut de gouvernance des identités machines (IoT)

- ISO 27001 : A.8.1 → A.5.16, A.8.5

