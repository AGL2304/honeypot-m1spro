/* hardened.c — version CORRIGÉE de vulnerable.c (M1SPRO J2).
 *
 * Même logique métier, mais la copie est BORNÉE à la taille du buffer et le
 * NUL terminal est garanti. Aucun débordement possible -> la variable d'état
 * ne peut plus être corrompue, quelle que soit la taille de l'entrée.
 *
 * Défenses appliquées (défense en profondeur) :
 *   - bornage explicite (`strncpy` + terminaison forcée) au niveau du code ;
 *   - compilation durcie (cf. Makefile : _FORTIFY_SOURCE, stack canary, PIE,
 *     RELRO, NX) -> filets de sécurité même en cas d'erreur résiduelle.
 */
#include <stdio.h>
#include <string.h>

static int check_access(const char *input) {
    char buffer[16];

    /* Borne stricte : au plus 15 octets copiés, NUL toujours présent. */
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    return strcmp(buffer, "open sesame") == 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <input>\n", argv[0]);
        return 2;
    }
    if (check_access(argv[1])) {
        printf("ACCES ACCORDE\n");
        return 0;
    }
    printf("Acces refuse\n");
    return 1;
}
