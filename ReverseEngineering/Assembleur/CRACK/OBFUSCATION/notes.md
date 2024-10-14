# Anti-Désassemblage

## Dead Code Inclusion 
- Implémentation : inclure du code qui n'est jamais exécuté
- Difficulté d'analyse : le code mort peut être confondu avec du code actif et complique l'analyse
- Exemple : insérer des focntions inutiles ou du code non atteignable en C

## Overlapping instructions
- Implémentation : instructions qui se chevauchent
- Difficulté d'analyse : les instructions se chevauchant peuvent être difficiles à identifier
- Exemple : `mov eax, 0x12345678` suivi de `mov ax, 0x9ABC` , les deux instructions se chevauchent

## ABI Violations 
- Implémentation : ne pas respecter les conventions d'appel standard
- Difficulté d'analyse : les conventions d'appel standard sont utilisées pour appeler des fonctions, si elles ne sont pas respectées, cela peut compliquer l'analyse
- Exemple: Modifier le registre de la base de la pile (EBP) ou le registre de la pile (ESP) sans les restaurer

## Code Chaining or Jumbling
- Implémentation : réorganiser les instructions pour rendre le code difficile à suivre
- Difficulté d'analyse : les instructions sont mélangées et difficiles à suivre en flux de contrôle
- Exemple : Utiliser des sauts indirects, trampolines et pointeurs de fonction en C (penser à des goto)

## Use of Opaque Predicates
- Implémentation : utiliser des conditions dont le résultat est connu, mais pas évident pour l'analyseur, ou claculer des adresses au runtime.
- Difficulté d'analyse : induit en erreur les outils d'analyse sur le flux de contrôle du programme
- Exemple : Utiliser des conditions qui sont toujours vraies ou fausses, mais complexes à évaluer
  
## Register Reassignment
- Implémentation : réaffectation des valeurs entre les registres pour des usages différents
- Difficulté d'analyse : les valeurs des registres sont modifiées de manière inattendue, et difficile de suivre les valeurs des données
- Exemple : rire en asm des transferts de registre apparemment non pertinents (xchg, mov, push/pop)


# Anti-Décompilation
## Forced Inlining
- Implémentation : utiliser des optimisations de compilateur pour forcer l'intégration de certaines fonctions
- Difficulté d'analyse : rend le flot de contrôle plus complexe et dissimule les limites de la fonction
- Exemple : Utiliser ```__attribute__((always_inline))``` en C pour forcer l'inline
  
## FOcntions qui ne pop pas autant qu elles push
- Implémentation : manipuler la pile pour déséquilibrer les opérations push pop
- Difficulté d'analyse : rend la décompilation plus difficile en raison de la manipulation de la pile
- Exemple : push rax;   *manquant un pop correspondant*

## Return Hijack (Stack Pivot)
- Implémentation : modifier la valeur de retour pour sauter à une autre fonction
- Difficulté d'analyse : rend la décompilation plus difficile en raison de la modification de la valeur de retour, déroutant pour les décompilateurs car flux de controle non conventionnel
- Exemple : ASM - xchg esp, eax : ret;
**[https://blog.ret2.io/2017/11/16/dangers-of-the-decompiler/]**

## Code Morphing
- Implémentation : le code s'auto-modifie pendant l'exécution
- Difficulté d'analyse : le code change pendant l'exécution rendant l'analyse statique non fiable
- Exemple : Générer du code avec un polymorphisme simple en C


## Garbage Code Insertion
- Implémentation : insérer du code inutile ou redondant
- Difficulté d'analyse : rend la décompilation plus difficile en raison de l'insertion de code inutile
- Exemple : insérer des instructions inutiles ou des instructions qui ne sont jamais exécutées, insérer des boucles no-op ou des instructions de saut inutiles

## Control flow Obfuscation
- Implémentation : altérer l'ordre des instructions, sauts indirects
- Difficulté d'analyse : rend la décompilation plus difficile en raison de l'altération du flux de contrôle
- Exemple : Utiliser des sauts indirects, des trampolines et des pointeurs de fonction en C (penser à des goto)
  
## Compilation Obfusquée
- Implémentation : utiliser des options de compilation pour rendre le code difficile à décompiler
- Difficulté d'analyse : rend la décompilation plus difficile en raison de l'optimisation du compilateur
- Exemple : Utiliser des options de compilation telles que -O3, -fomit-frame-pointer, -finline-functions, -finline-limit, -fmerge-all-constants, -fmerge-constants, -fmerge-all-constants, -fmerge-constants, -fno-inline, ```obfuscator-llvm```

## Symbol Stripping
- Implémentation : supprimer les symboles du binaire avec des outils comme strip
- Difficulté d'analyse : rend la décompilation plus difficile en raison de la suppression des symboles
- Exemple : commande ```-strip --strip-all executable ```
  
## Symbol renaming/shuffling
- Implémentation : renommer les symboles pour rendre la décompilation plus difficile avec des outils comme objcopy sur Linux
- Difficulté d'analyse : rend la décompilation plus difficile en raison du renommage des symboles et sur l'action des fonctions
- Exemple : ```objcopy --redefine-sym strcmp=printf old=new executable```
  
## Static Linking
- Implémentation : lier statiquement les bibliothèques pour rendre la décompilation plus difficile
- Difficulté d'analyse : rend la décompilation plus difficile en raison de la liaison statique
- Exemple : ```gcc -static -o executable source.c```

## Obfuscation des litérales
- Implémentation : changer les valeurs constantes en calculs, appels de fonction ou en string XORées
- Difficulté d'analyse : rend les valeurs difficiles à reconnaître et à interpréter
- Exemple : Remplacer une valeur constante par un calcul redondant en C
  
**Concretement les malfaiteurs craquent souvent certains logiciels en très peu de temps à cause de la présence de litérales en dur, correspondant comme par hasard à la durée de la version d'évaluation.**

## APIU Obfusctation
- Implémentation : renommer et créer des wrappers autour des appels API et appels système
- Difficulté d'analyse : cache l'utilisation directe des API nécessitant une analyse plus profonde
- Exemple : Wrapper des appels système en C
  
# Anti-Debugging

## Timing Analysis
- Implémentation : mesurer le temps d'exécution pour détecter les outils de débogage
- Difficulté d'analyse : rend la détection des outils de débogage plus difficile
- Exemple : Mesurer le temps entre les points de contrôle en C

## VM Sandbox Detection
- Implémentation : vérifier les artefacts indiquant l'exécution dans une machine virtuelle ou une sandbox
- Difficulté d'analyse : peut refuser de s'exécuter ou altérer le comportement dans un VM
- Exemple : Vérifier les artefacts de VirtualBox, VMware, QEMU, valeurs de registre, cache de navigateur, etc.

## Check COmmon Debuggers in Parent Proc
- Implémentation : vérifier les processus parents pour les débogueurs courants
- Difficulté d'analyse : Peut empêcher le débogage en détectant les débogueurs
- Exemple : Vérifier les processus parents pour gdb, ollydbg, x64dbg, windbg, etc.

## /proc/self/status (TracerPID Line)
- Implémentation : vérifier la ligne TracerPid /proc/self/status pour le PID du débogueur
- Difficulté d'analyse : Détecte la plupart des débogueurs attachés sous linux
- Exemple : Vérifier le fichier /proc/self/status pour le PID du débogueur dans le C

## PTRACE_TraceMe
- Implémentation : vérifier si le processus est tracé par un débogueur et lancer un auto-débug pour empecher l utilisateur d en lancer un autre

## Runtime Integrity Checks
- Implémentation : vérifier l'intégrité du processus en vérifiant les valeurs de hachage, les signatures, les checksums
- Difficulté d'analyse : peut détecter et réagir à la modification du code comme la présence de l'instruction INT3
- Exemple : Vérifier les sommes de contrôle de segments de code en C

