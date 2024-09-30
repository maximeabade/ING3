#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

// Cette fois, le buffer est beaucoup plus petit... Soyez créatif !
// Utilisez Google pour trouver des shellcodes plus compacts, et ajustez
// le code ASM si nécessaire.
// Comme l'ASLR est activé, l'adresse du buffer vous est fournie pour
// simplifier la tâche.

void getstr(char *b) {
    while((*b = getchar()) && *b != '\n') b++; *b = '\0';
}

int main() {
    int isadmin = 0;
    char buffer[15];

    printf("DEBUG: buffer is at %p\n\n", buffer);
    printf("Veuillez entrer votre mot de passe:\n");
    getstr(buffer);
    if (isadmin == 256)
        system("/bin/sh");
    return 0;
}