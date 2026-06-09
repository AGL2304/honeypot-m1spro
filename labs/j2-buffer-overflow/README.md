# Lab J2 — Sécurité mémoire / buffer overflow

Démonstration du jour 2 du programme M1SPRO « Sécurité en Programmation ».
Comme `secure_app` est écrite en Python (langage *memory-safe*), cette classe
de vulnérabilité ne s'y applique pas : on l'illustre donc sur un programme **C**
dédié, vulnérable puis corrigé.

## Fichiers

| Fichier | Rôle |
|---|---|
| `vulnerable.c` | Code volontairement vulnérable : `strcpy` non borné -> stack overflow (CWE-121). |
| `hardened.c` | Version corrigée : copie bornée (`strncpy` + NUL forcé). |
| `Makefile` | Compile 3 variantes (sans mitigation / avec canari / durcie). |
| `run_demo.sh` | Compile et compare les 4 comportements côte à côte. |

## Lancer (Linux / WSL — nécessite `gcc`, `make`, `python3`)

```bash
bash run_demo.sh
```

Sortie attendue :

| Cas | Binaire | Entrée | Résultat |
|---|---|---|---|
| 1 | non durci | `open sesame` | `ACCES ACCORDE` (légitime) |
| 2 | non durci | 64×`A` | **`ACCES ACCORDE` sans mot de passe** → exploit |
| 3 | + canari | 64×`A` | `*** stack smashing detected ***`, abort (rc 134) |
| 4 | corrigé + durci | 64×`A` | `Acces refuse`, aucun crash |

## Les mitigations (vues en J2)

- **Bornage du code** (cas 4) — la *vraie* correction : `strncpy`, `snprintf`,
  `fgets` au lieu de `strcpy`/`gets`/`sprintf`. Supprime le bug à la racine.
- **Stack canary** (`-fstack-protector-all`) — valeur sentinelle vérifiée à la
  sortie de fonction ; détecte l'écrasement et abort avant l'exploitation.
- **NX / DEP** (`-z noexecstack`) — la pile n'est pas exécutable (bloque le
  shellcode classique).
- **ASLR + PIE** (`-fPIE -pie`) — randomise les adresses (casse les ROP/ret2libc
  prévisibles).
- **RELRO** (`-z relro,-z now`) — GOT en lecture seule (bloque le GOT overwrite).
- **`_FORTIFY_SOURCE=2`** — vérifications de bornes à la compilation/exécution
  pour les fonctions de la libc.

## Lien avec le reste du projet

Ce lab est vérifié automatiquement en CI (job `j2-memory-safety`) : on compile
les binaires et on **prouve** que (3) le canari intercepte l'overflow (SIGABRT)
et que (4) la version durcie y résiste sans crash.
