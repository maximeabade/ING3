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
  
