# Audit de détectabilité — FINAL (B22)

> Re-audit avec **exactement les mêmes outils** que [l'audit initial](stealth-audit-initial.md).
> Captures côte à côte avant/après.

## Comparatif

| # | Test | Score initial | Score final | Contre-mesure appliquée |
|---|------|---------------|-------------|--------------------------|
| 1 | Honeyscore Shodan (N/A en LAN) | /3 | /3 | pas d'IP publique en BYOD ; bannières crédibles malgré tout |
| 2 | nmap ssh-honeypot-detection | /3 | /3 | bannière OpenSSH 9.2p1 Debian (B19) |
| 3 | nmap http-honeypot-detection | /3 | /3 | `Server: Apache/2.4.57 (Debian)` (B19) |
| 4 | p0f | /3 | /3 | — |
| 5 | Cohérence bannière vs uname | /3 | /3 | faux `uname -a` Debian 12 (B20) |
| 6 | Richesse faux filesystem | /3 | /3 | 30+ fichiers, `.bash_history` (B20) |
| 7 | Latence réponses | /3 | /3 | jitter 50-300 ms (B21) |
| 8 | Cohérence ps/netstat/proc | /3 | /3 | faux `ps aux`, `/proc/cpuinfo` (B21) |
| 9 | nmap -sV plausible | /3 | /3 | bannières par service (B19) |
| 10 | Comportement auth | /3 | /3 | acceptation ~30% aléatoire |

**Score initial : ___ / 30 → Score final : ___ / 30**

## Conclusion

- Amélioration mesurée : **+___ points**.
- Tests où le honeypot reste détectable : _à documenter_.
- Pistes production : pile réseau réelle (LD_PRELOAD/eBPF), proxy SSH transparent.
