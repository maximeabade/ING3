Voici un mémo en Markdown pour coder en assembleur x86-64, qui couvre les bases essentielles et les commandes courantes.

---

# Mémo pour la Programmation en Assembleur x86-64

## Introduction

La programmation en assembleur x86-64 implique l'écriture de code bas niveau qui est directement traduit en instructions machine pour l'architecture x86-64. Ce mémo couvre les sections de base, les instructions courantes, et les syscalls.

## Sections du Code

1. **Section `.data`**
   - Contient les données initialisées.
   - Exemple : Déclaration de chaînes de caractères, constantes.

   ```asm
   section .data
       message db 'Hello, World!', 0
   ```

2. **Section `.bss`**
   - Contient les données non initialisées.
   - Exemple : Variables non initialisées.

   ```asm
   section .bss
       buffer resb 256  ; Réserve 256 octets
   ```

3. **Section `.text`**
   - Contient le code exécutable.
   - Exemple : Le code du programme.

   ```asm
   section .text
       global _start  ; Déclaration du point d'entrée
   ```

## Instructions de Base

- **Déplacement de Données**
  - `mov <destination>, <source>` : Déplace les données de la source vers la destination.
  - Exemple : `mov rax, 5` (déplace 5 dans le registre RAX).

- **Opérations Arithmétiques**
  - `add <destination>, <source>` : Ajoute la source à la destination.
  - `sub <destination>, <source>` : Soustrait la source de la destination.
  - Exemple : `add rax, rbx` (ajoute la valeur de RBX à RAX).

- **Comparaisons**
  - `cmp <op1>, <op2>` : Compare deux opérandes en soustrayant `op2` de `op1`.
  - Exemple : `cmp rax, rbx` (compare les valeurs de RAX et RBX).

- **Saute Conditionnel**
  - `je <label>` : Saut à `<label>` si la comparaison est égale.
  - `jne <label>` : Saut à `<label>` si la comparaison n'est pas égale.
  - Exemple : `je end` (saut à `end` si la comparaison précédente est égale).

- **Appels Système (Syscalls)**
  - Utilisé pour interagir avec le noyau du système d'exploitation.
  - `mov rax, <num_syscall>` : Charge le numéro du syscall dans RAX.
  - `syscall` : Effectue l'appel système.
  - Exemple : Écrire un message dans stdout.

## Exemple de Code : "Hello, World!"

```asm
section .data
    hello db 'Hello, World!', 0

section .text
    global _start

_start:
    ; write(1, hello, 13)
    mov rax, 1          ; syscall number (sys_write)
    mov rdi, 1          ; file descriptor (stdout)
    mov rsi, hello      ; pointer to the message
    mov rdx, 13         ; message length
    syscall             ; call kernel

    ; exit(0)
    mov rax, 60         ; syscall number (sys_exit)
    xor rdi, rdi        ; exit code 0
    syscall             ; call kernel
```

## Répertoires des Registres

- **Registres Généraux :** `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, etc.
- **Registres de Pointeur :** `rsp` (pointeur de pile), `rbp` (base de pile).
- **Registres de Segment :** `cs`, `ds`, `es`, `fs`, `gs`, `ss`.

## Compilation et Exécution

### Sous Windows

1. **Installer NASM et LD**
2. **Compiler**
   ```bash
   nasm -f elf64 hello.asm -o hello.o
   ld hello.o -o hello
   ```
3. **Exécuter**
   ```bash
   hello
   ```

### Sous Linux

1. **Installer NASM**
   ```bash
   sudo apt-get update
   sudo apt-get install nasm gcc
   ```
2. **Compiler**
   ```bash
   nasm -f elf64 hello.asm -o hello.o
   ld hello.o -o hello
   ```
3. **Exécuter**
   ```bash
   ./hello
   ```





Créer des fonctions en assembleur x86-64 est une tâche fondamentale pour structurer ton code et favoriser la réutilisabilité. Voici comment tu peux définir et appeler des fonctions en assembleur, avec des exemples pratiques.

## Création de Fonctions en Assembleur x86-64

### 1. **Définir une Fonction**

Pour définir une fonction, tu crées un label qui sert de point d'entrée pour la fonction. Le code de la fonction doit préserver les registres utilisés et s'assurer de retourner au bon endroit.

#### Exemple de Fonction en Assembleur

```asm
section .data
    msg db 'Result: ', 0  ; Message pour afficher le résultat

section .bss
    result resb 10         ; Réserve un espace pour afficher le résultat

section .text
    global _start          ; Point d'entrée pour l'éditeur de liens
    extern my_function     ; Déclaration de la fonction externe

_start:
    ; Appeler la fonction
    mov rdi, 5             ; Passer l'argument 5 dans RDI
    call my_function       ; Appeler la fonction

    ; Code pour afficher le résultat
    mov rax, 1             ; syscall number (sys_write)
    mov rdi, 1             ; file descriptor (stdout)
    mov rsi, msg           ; pointer to the message
    mov rdx, 8             ; length of the message
    syscall                ; call kernel

    ; Exit
    mov rax, 60            ; syscall number (sys_exit)
    xor rdi, rdi           ; exit code 0
    syscall                ; call kernel

; Définir la fonction
my_function:
    push rbx               ; Sauvegarder le registre RBX
    mov rbx, rdi           ; Passer l'argument dans RBX (ici, on suppose que l'argument est dans RDI)
    
    ; Calculer quelque chose (exemple simple : multiplication par 2)
    shl rbx, 1             ; Multiplier RBX par 2

    ; Convertir le résultat en chaîne (ici, il est juste placé dans `result`)
    mov [result], rbx      ; Stocker le résultat dans `result`

    pop rbx                ; Restaurer le registre RBX
    ret                    ; Retourner à l'appelant
```

### 2. **Appeler une Fonction**

Pour appeler une fonction en assembleur, tu utilises l'instruction `call`. Voici comment passer des arguments et recevoir des résultats :

- **Passer des Arguments :**
  - **Premier argument** : `rdi`
  - **Deuxième argument** : `rsi`
  - **Troisième argument** : `rdx`
  - **Quatrième argument** : `rcx`
  - **Cinquième argument** : `r8`
  - **Sixième argument** : `r9`
  - Les arguments suivants doivent être passés via la pile.

- **Appeler la Fonction :**
  ```asm
  mov rdi, 5         ; Placer l'argument dans rdi
  call my_function   ; Appeler la fonction
  ```

- **Retourner des Résultats :**
  - Le résultat d'une fonction est généralement retourné dans `rax`.

### 3. **Respecter les Conventions d'Appel**

Sur les systèmes x86-64, il est important de suivre les conventions d'appel pour éviter les conflits :

- **Registres à Sauvegarder :** Les fonctions doivent sauvegarder les registres qu'elles utilisent si elles souhaitent les modifier (comme `rbx`, `r12`, `r13`, `r14`, `r15`).
- **Registres à Préserver :** Les fonctions peuvent modifier les registres `rax`, `rcx`, `rdx`, `rsi`, `rdi`, mais doivent restaurer les valeurs originales des registres qu'elles modifient si elles veulent les utiliser pour retourner des valeurs ou pour des appels système.

### 4. **Exemple Complet de Fonction et d'Appel**

Voici un exemple complet où une fonction additionne deux nombres et retourne le résultat.

```asm
section .data
    msg db 'Sum: ', 0   ; Message pour afficher la somme
    newline db 10       ; Nouvelle ligne

section .text
    global _start
    extern add_numbers

_start:
    ; Appeler la fonction
    mov rdi, 10         ; Premier argument (10)
    mov rsi, 20         ; Deuxième argument (20)
    call add_numbers    ; Appeler la fonction

    ; Afficher le résultat
    mov rax, 1          ; syscall number (sys_write)
    mov rdi, 1          ; file descriptor (stdout)
    mov rsi, msg        ; pointer to the message
    mov rdx, 4          ; length of the message
    syscall             ; call kernel

    ; Afficher le résultat (nécessite conversion en chaîne)
    ; (Omitted: Convertir le résultat en chaîne et afficher)

    ; Ajouter une nouvelle ligne
    mov rsi, newline    ; pointer to newline
    mov rdx, 1          ; length of newline
    syscall             ; call kernel

    ; Exit
    mov rax, 60         ; syscall number (sys_exit)
    xor rdi, rdi        ; exit code 0
    syscall             ; call kernel

; Définir la fonction
add_numbers:
    ; Arguments : rdi = premier nombre, rsi = deuxième nombre
    add rdi, rsi        ; Additionner rsi à rdi
    mov rax, rdi        ; Placer le résultat dans rax (valeur de retour)
    ret                 ; Retourner à l'appelant
```

