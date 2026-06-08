# Attribution de l'IP source : local (passerelle Docker) vs distant (vraie IP)

> Constat opérationnel observé pendant les tests d'attaque (P5 / préparation J5).
> Explique pourquoi une attaque jouée **depuis l'hôte** s'effondre sur une seule
> IP, alors qu'une attaque **depuis une autre machine** conserve sa vraie source.
> Conséquence directe sur la valeur probante du dashboard et des exports IOC.

## TL;DR

| Origine de l'attaque | IP vue par le honeypot | Pourquoi |
|----------------------|------------------------|----------|
| Hôte → `127.0.0.1:<port publié>` | **passerelle du bridge Docker** (ex. `172.21.0.1`) | SNAT : le trafic localhost qui traverse les ports publiés est ré-écrit avec l'IP de la gateway du réseau bridge |
| Machine distante → `192.168.56.104:<port>` | **vraie IP de l'attaquant** (ex. `192.168.56.1`) | DNAT : iptables redirige vers le conteneur **en préservant** l'adresse source d'origine |

**Règle à retenir pour la démo :** pour prouver l'attribution par IP, il faut
attaquer **depuis une autre machine** (LAN inter-équipes / host-only), jamais
depuis `localhost`.

## Preuve mesurée (notre stack)

Endpoint `GET /attackers` de l'analyzer, après deux campagnes :

| IP source | Événements | Classification | Origine réelle |
|-----------|-----------:|----------------|----------------|
| `172.21.0.1` | ~19 000 | `humain` | toutes les attaques jouées **en local** sur la VM Kali (collapse sur la gateway) |
| `192.168.56.1` | 496 | `bot` | campagne multi-services lancée **depuis Windows** (host-only) vers le honeypot Kali |

Les 496 events distants se ventilent par service (telnet 214, ftp 151, http 102,
ssh 29) et restent **distincts** de la masse locale — exactement ce qu'on veut
montrer au jury : le pipeline attribue, géolocalise et classe une **source
distincte et réelle**.

## Détail technique

Docker publie un port (`-p 22:2222`) via une règle **DNAT** dans la chaîne
`DOCKER` de `nat`. Le chemin du paquet diffère selon l'origine :

- **Trafic distant** (autre hôte du LAN) : le paquet arrive sur l'interface
  physique, le DNAT change uniquement la destination (IP hôte → IP conteneur).
  L'adresse **source est conservée** → le honeypot voit la vraie IP de
  l'attaquant. C'est le cas réaliste.

- **Trafic localhost** (`127.0.0.1` ou IP de l'hôte depuis l'hôte) : pour que la
  réponse revienne correctement, Docker applique en plus un **MASQUERADE (SNAT)**
  sur le réseau bridge. La source est ré-écrite avec l'IP de la **gateway du
  bridge** (`172.x.0.1`). Tous les clients locaux se confondent donc en une seule
  IP, et la géoloc/le scoring perdent leur sens.

## Conséquences

1. **Dashboard / scoring** : une démo « localhost » donne 1 seul attaquant
   artificiel — peu convaincant. Une démo « machine distante » donne une carte
   d'attaquants crédible.
2. **Exports défensifs (B17/B24)** : la `block_list.iptables` et les `iocs.json`
   ne valent que si l'IP source est réelle. Bloquer `172.21.0.1` (sa propre
   gateway) serait absurde — encore une raison d'attaquer depuis l'extérieur.
3. **RGPD (charte)** : les IP distantes sont des **données personnelles**. En
   contexte pédagogique LAN inter-équipes c'est maîtrisé, mais tout partage de
   dataset doit passer par l'anonymisation prévue dans `docs/charte-rgpd.md`.

## Reproduire (P5)

```bash
# Depuis une AUTRE machine du LAN (ex. Windows host-only 192.168.56.1)
#   cible = IP host-only de la VM honeypot (ex. 192.168.56.104)
bash attacks/run_all.sh 192.168.56.104

# Sur la VM honeypot, vérifier l'attribution :
dc exec -T analyzer python -c "import urllib.request,json; \
print(json.load(urllib.request.urlopen('http://localhost:8000/attackers')))"
# -> la vraie IP source apparaît, distincte de la gateway 172.x.0.1
```

## Panneau « Sources géolocalisées » du dashboard (vide en LAN/BYOD)

Le panneau geomap *« Sources géolocalisées (déploiement public) »* du dashboard
Grafana est **vide par conception** dans notre déploiement, pour deux raisons
cumulées :

1. **IP privées non géolocalisables.** Le panneau interroge
   `SELECT latitude, longitude ... WHERE latitude IS NOT NULL`. La latitude n'est
   renseignée que par l'enricher GeoIP (`analyzer/enrichers/geoip.py`, base
   MaxMind GeoLite2). MaxMind ne retourne **aucune** position pour les plages
   privées/réservées (`172.x`, `192.168.x`, `127.x`) — or ce sont précisément nos
   sources en LAN/BYOD. La colonne `latitude` reste donc `NULL`.
2. **Base GeoLite2 optionnelle.** `data/geoip/GeoLite2-City.mmdb` (compte école)
   est facultative ; absente, l'enricher renvoie `{}` et aucun event n'est
   géolocalisé. C'est une dégradation prévue (cf. README §Dépannage).

C'est cohérent avec le syllabus révisé (BYOD/no-VPS) : le scénario « déploiement
public » qui justifiait ce panneau a été retiré. Le panneau porte désormais une
**description info-bulle** expliquant ce comportement.

**Pour l'allumer (optionnel, démo)** : déposer `data/geoip/GeoLite2-City.mmdb`
**et** rejouer un dataset d'attaques à **IP publiques** (B23 — replay dataset).
Vérification rapide du nombre d'events géolocalisés :

```bash
dc exec -T postgres psql -U honeypot -d honeypot -tc \
  "SELECT count(*) FILTER (WHERE latitude IS NOT NULL) AS geoloc, count(*) AS total FROM events;"
```

## Pistes production (hors périmètre BYOD)

- Déploiement avec IP publique dédiée par service (pas de SNAT parasite).
- `userland-proxy: false` côté Docker + bridge dédié pour limiter le masquage.
- Proxy/reverse-proxy conservant `X-Forwarded-For` et `PROXY protocol` pour les
  services applicatifs.
