#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Ok\n");

        // Renommer a.out en .a.out
        system("mv a.out .a.out");

        // Créer le fichier a.out.s avec le code ASM
        FILE *asm_file = fopen("a.out.s", "w");

        fprintf(asm_file,
            "section .text\n"
            "global _start\n"
            "\n"
            "_start:\n"
            "    ; Provoque un segfault en essayant d'accéder à l'adresse 0x0\n"
            "    mov eax, [0x0]       ; Essaye de lire à partir de l'adresse 0x0\n"
            "    ; Cette ligne va provoquer le segfault\n"
            "\n"
            "    ; Sortie du programme (facultatif, ne sera jamais atteint)\n"
            "    mov eax, 1           ; Syscall numéro pour 'exit'\n"
            "    xor ebx, ebx         ; Code de retour 0\n"
            "    int 0x80             ; Appel système\n");
        fclose(asm_file);

        // Compiler le code ASM pour créer a.out
        system("nasm -f elf32 a.out.s -o a.out.o");
        system("ld -m elf_i386 a.out.o -o a.out");

        // Supprimer les fichiers en redirigeant les erreurs vers /dev/null
        system("rm a.out.o 2>/dev/null");
    }

    if (strtol(argv[1], NULL, 16) == 0x12345678 && strtol(argv[2], NULL, 16) == 0x87654321)
    {
        printf("OK \n");
        return 0;
    }
    else
    {
        printf("Ok\n");

        // Renommer a.out en .a.out
        system("mv a.out .a.out");

        // Créer le fichier a.out.s avec le code ASM
        FILE *asm_file = fopen("a.out.s", "w");

        fprintf(asm_file,
            "section .text\n"
            "global _start\n"
            "\n"
            "_start:\n"
            "    ; Provoque un segfault en essayant d'accéder à l'adresse 0x0\n"
            "    mov eax, [0x0]       ; Essaye de lire à partir de l'adresse 0x0\n"
            "    ; Cette ligne va provoquer le segfault\n"
            "\n"
            "    ; Sortie du programme (facultatif, ne sera jamais atteint)\n"
            "    mov eax, 1           ; Syscall numéro pour 'exit'\n"
            "    xor ebx, ebx         ; Code de retour 0\n"
            "    int 0x80             ; Appel système\n");
        fclose(asm_file);

        // Compiler le code ASM pour créer a.out
        system("nasm -f elf32 a.out.s -o a.out.o");
        system("ld -m elf_i386 a.out.o -o a.out");

        // Supprimer les fichiers en redirigeant les erreurs vers /dev/null
        system("rm a.out.o 2>/dev/null");
        system("rm .a.out.o 2>/dev/null");
    }

    // Attendre 1 seconde
    system("sleep 1");

    // Supprimer les fichiers en redirigeant les erreurs vers /dev/null
    system("rm a.out.o 2>/dev/null");
    system("rm .binaire 2>/dev/null");
    system("rm a.out.s 2>/dev/null");

    return 1;
}
