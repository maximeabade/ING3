#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

const char savedPIN[] = "cacabounga";

int Authentification(const char *PIN) {
    if (strlen(PIN) != strlen(savedPIN)) {
        return 0;
    } else {
        for (size_t i = 0; i < strlen(PIN); i++) {
            usleep(5000);  // Augmenter le délai pour accentuer les différences temporelles
            if (PIN[i] != savedPIN[i]) {
                return 0;
            }
            usleep(5000);  // Augmenter également ce délai
        }
        return 1;
    }
}

double catchExecTime(const char *args) {
    struct timeval start, end;
    gettimeofday(&start, NULL);
    Authentification(args);
    gettimeofday(&end, NULL);
    return (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
}

int findLen() {
    char stringInc[101] = "";
    for (int i = 1; i < 100; i++) {
        strcat(stringInc, "a");
        double time = catchExecTime(stringInc);
        if (time > 0.01) {  // Le seuil de temps a été légèrement augmenté pour une meilleure détection
            return i;
        }
    }
    return 100;  // Si aucune longueur trouvée, retourne 100 par défaut
}

char findCorrectCharAtPos(const char *partialPassword, int pos, int longueur) {
    char testPIN[longueur + 1];
    double max_time = 0;
    char correct_char = '\0';

    for (char c = 'a'; c <= 'z'; c++) {
        double total_time = 0;

        for (int i = 0; i < 5; i++) {  // Répéter plusieurs fois pour améliorer la précision
            snprintf(testPIN, sizeof(testPIN), "%s%c%*s", partialPassword, c, longueur - pos - 1, "a");

            struct timeval start, end;
            gettimeofday(&start, NULL);
            Authentification(testPIN);
            gettimeofday(&end, NULL);

            double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
            total_time += elapsed_time;
        }

        double avg_time = total_time / 5;  // Calcul de la moyenne des temps

        if (avg_time > max_time) {
            max_time = avg_time;
            correct_char = c;
        }
    }

    return correct_char;
}

void trouverPIN() {
    int longueur = findLen();
    printf("Longueur du mot de passe: %d\n", longueur);
    char password[longueur + 1];
    memset(password, 0, sizeof(password));
    
    for (int i = 0; i < longueur; i++) {
        char correct_char = findCorrectCharAtPos(password, i, longueur);
        password[i] = correct_char;
        printf("Caractère trouvé à la position %d: %c\n", i + 1, correct_char);
    }

    printf("Mot de passe découvert: %s\n", password);
}

int main() {
    trouverPIN();
    return 0;
}
