# Lab J2 — sécurité mémoire. Compile 3 variantes pour comparer les mitigations.
CC ?= gcc

# (1) « Naïf » : mitigations modernes DÉSACTIVÉES -> expose le bug.
NOMIT_FLAGS = -O0 -g -fno-stack-protector -no-pie -fno-pic

# (2) Même source mais AVEC canari de pile (détection à la sortie de fonction).
CANARY_FLAGS = -O0 -g -fstack-protector-all -no-pie

# (3) Version corrigée + durcissement complet (profil distro durci).
HARDEN_FLAGS = -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-all -fPIE -pie \
               -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wformat -Wformat-security

.PHONY: all clean
all: vuln_nomit vuln_canary hardened

vuln_nomit: vulnerable.c
	$(CC) $(NOMIT_FLAGS) -o $@ $<

vuln_canary: vulnerable.c
	$(CC) $(CANARY_FLAGS) -o $@ $<

hardened: hardened.c
	$(CC) $(HARDEN_FLAGS) -o $@ $<

clean:
	rm -f vuln_nomit vuln_canary hardened
