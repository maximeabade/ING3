# Désassemblage

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