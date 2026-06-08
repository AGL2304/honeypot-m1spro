# Audit de détectabilité — INITIAL (B18)

> Gabarit à remplir avec les **captures d'écran** des outils. Score sur /30.
> À réaliser **avant** les contre-mesures de furtivité (B19-B21).

## Méthodologie

Mêmes outils que le re-audit final (B22) pour garantir la comparabilité.

| # | Test | Outil | Résultat observé | Score (0-3) | Capture |
|---|------|-------|------------------|-------------|---------|
| 1 | Probabilité honeypot | Honeyscore Shodan | _à remplir_ | /3 | `[screenshot]` |
| 2 | Détection SSH honeypot | `nmap --script ssh-honeypot-detection` | | /3 | |
| 3 | Détection HTTP honeypot | `nmap --script http-honeypot-detection` | | /3 | |
| 4 | Empreinte pile TCP/IP | `p0f` | | /3 | |
| 5 | Cohérence bannière vs uname | check manuel | | /3 | |
| 6 | Richesse du faux filesystem | check manuel | | /3 | |
| 7 | Latence des réponses (constante ?) | mesure manuelle | | /3 | |
| 8 | Cohérence `ps`/`netstat`/`/proc` | check manuel | | /3 | |
| 9 | Versions `nmap -sV` plausibles | `nmap -sV` | | /3 | |
| 10 | Comportement auth (toujours accept ?) | check manuel | | /3 | |

**Score initial : ___ / 30**

## Commandes de référence

```bash
nmap -sV -p 22,80,21,23 <cible>
nmap --script ssh-honeypot-detection -p 22 <cible>
nmap --script http-honeypot-detection -p 80 <cible>
sudo p0f -i eth0
# Honeyscore : https://honeyscore.shodan.io/ (cible exposée)
```

## Faiblesses identifiées (à corriger en B19-B21)

- _ex : bannière SSH générique, latence trop régulière, faux fs pauvre…_
