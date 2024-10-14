# Désassemblage

## Dead Code Inclusion 
- Implémentation : inclure du code qui n'est jamais exécuté
- Difficulté d'analyse : le code mort peut être confondu avec du code actif et complique l'analyse
- Exemple : insérer des focntions inutiles ou du code non atteignable en C

## Overlapping instructions
- Implémentation : instructions qui se chevauchent
- Difficulté d'analyse : les instructions se chevauchant peuvent être difficiles à identifier
- Exemple : `mov eax, 0x12345678` suivi de `mov ax, 0x9ABC` , les deux instructions se chevauchent

