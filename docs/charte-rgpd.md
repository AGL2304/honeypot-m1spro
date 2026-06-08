# Charte de collecte de données — Honeypot M1SPRO (B0)

> Document à personnaliser et **signer par les 4 membres de l'équipe** avant toute
> mise en service. Conforme aux recommandations ENISA *Proactive Detection of
> Security Incidents — Honeypots*.

## 1. Finalité de la collecte

Ce honeypot est déployé dans un **but pédagogique et de recherche défensive**
(formation M1 CyberSécurité, École IT). Il vise à :

- observer et caractériser les comportements d'attaquants ;
- valider une chaîne de détection (capture → classification → enrichissement) ;
- produire des indicateurs de compromission (IOC) à des fins défensives.

Il **n'a pas** vocation à piéger une personne identifiée ni à provoquer une
infraction (pas d'*entrapment*).

## 2. Base légale et cadre juridique

- **RGPD** : les adresses IP collectées sont des **données à caractère personnel**
  (CJUE, arrêt Breyer C-582/14). Base légale retenue : **intérêt légitime**
  (art. 6.1.f RGPD) — sécurité du système d'information.
- **Article 323-1 du Code pénal** (accès/maintien frauduleux dans un STAD) :
  le honeypot est un système **dédié**, isolé, sans donnée réelle ; aucune
  donnée de tiers n'est exposée.
- **Minimisation** (art. 5.1.c RGPD) : seules les données strictement nécessaires
  à l'analyse de l'attaque sont conservées.

## 3. Données collectées

| Donnée | Finalité | Sensibilité |
|---|---|---|
| IP source, port | Origine de l'attaque, enrichissement géo/réputation | Personnelle |
| Horodatage | Corrélation temporelle | Faible |
| Identifiants tentés (login/pass) | Analyse des dictionnaires | Potentiellement personnelle |
| Commandes / requêtes HTTP / payloads | Analyse comportementale, mapping ATT&CK | Variable |
| User-Agent, bannières | Fingerprinting des outils | Faible |

## 4. Durée de conservation

- Données brutes : **30 jours** maximum après la fin du projet.
- Données anonymisées (statistiques, IOC) : conservation possible à des fins
  pédagogiques.

## 5. Anonymisation / pseudonymisation

Avant tout partage ou remise (dump J5), les IP sources sont **tronquées**
(dernier octet masqué : `203.0.113.x`) ou hachées (SHA-256 + sel) selon le besoin
d'analyse. Aucune donnée brute non anonymisée n'est diffusée hors de l'équipe.

## 6. Sécurité du dispositif

- Conteneurs **non-root**, **read-only**, `cap-drop ALL`, réseau isolé.
- Impossibilité de pivot vers le réseau interne (cf. `docs/` et `infra/`).
- Intégrité des logs (option : signature des fichiers, cf. M1CRYP).

## 7. Limites éthiques

- Pas de contre-attaque, pas de *hack-back*.
- Pas de collecte au-delà du périmètre du honeypot.
- Retrait immédiat du dispositif (LAN de salle / rejeu de datasets) à la fin de la fenêtre de démo (J5).

## 8. Signatures

| Membre | Rôle (binôme) | Date | Signature |
|---|---|---|---|
| _________ | A — Offensive/Validation | __/__/____ | |
| _________ | A — Offensive/Validation | __/__/____ | |
| _________ | B — Construction/Blue Team | __/__/____ | |
| _________ | B — Construction/Blue Team | __/__/____ | |
