/* vulnerable.c — DÉMONSTRATION PÉDAGOGIQUE (M1SPRO J2, sécurité mémoire).
 *
 * ⚠️ Code VOLONTAIREMENT vulnérable. Ne JAMAIS réutiliser tel quel.
 *
 * Le bug : `strcpy` copie une entrée de taille arbitraire dans un buffer de
 * 16 octets sur la pile. En débordant, l'attaquant écrase la variable locale
 * `authenticated` (adjacente sur la pile) et obtient l'accès SANS le mot de
 * passe — c'est l'archétype du stack buffer overflow (CWE-121, cf. Morris
 * 1988, Code Red 2001).
 *
 * Compilé SANS canari (-fno-stack-protector) : l'exploit passe silencieusement.
 * Compilé AVEC canari (-fstack-protector-all) : la corruption est détectée à
 * la sortie de fonction -> « *** stack smashing detected *** » + abort().
 */
#include <stdio.h>
#include <string.h>

int check_access(const char *input) {
    int authenticated = 0;       /* 0 = refusé par défaut */
    char buffer[16];             /* trop petit, aucune borne */

    strcpy(buffer, input);       /* VULN : copie non bornée -> débordement */

    if (strcmp(buffer, "open sesame") == 0) {
        authenticated = 1;       /* chemin légitime */
    }
    return authenticated;        /* peut avoir été écrasé par l'overflow */
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
