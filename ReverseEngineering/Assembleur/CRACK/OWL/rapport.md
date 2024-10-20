
# Reverse Engineering
## Crack My Owl

### 2024/2025

---

## Résumé

```bash
./owl 3333333333333333333333333333333333333 
./05 ROBINET 
./06 2000 -50
./07 2859 
./08 g00d3n0ugh 
./09 9876543210
```

---

### OWL

Pour commencer, j'ai chargé le binaire ELF patché dans Ghidra. L'objectif était de comprendre la structure du code et d'identifier les sections importantes, en particulier celles qui traitent des arguments d'entrée ou du mot de passe.

Cependant, lors de l'exploration initiale, j'ai remarqué que le programme utilisait une nouvelle forme d'obfuscation. Plus précisément, il y avait un jump indirect basé sur le contenu d’un registre, ce qui signifie que l'adresse de saut est dynamique, ce qui rend l'analyse statique dans Ghidra impossible. Je récupère toutefois l'adresse de l’entry point.

Je décide donc d’ouvrir en parallèle GDB pour faire de l’analyse dynamique en parallèle et comprendre ce qu'il se passe au niveau des registres pendant l'exécution du programme. Je pose un breakpoint à l'entry point, lance le programme et inspecte le contenu du registre RBX (celui utilisé pour le jmp). Je remarque qu’il faut mettre un argument lors du lancement du programme pour jmp au bon endroit.

J’identifie par la suite une comparaison impliquant le registre `cl` et la valeur `0x25` (37 en décimal). J'en déduis après plusieurs tests d'argument que cette valeur correspond au nombre de caractères attendu pour le mot de passe. Ainsi, le mot de passe à fournir doit être long de 37 caractères.

En continuant l'exploration, j’identifie finalement une autre comparaison importante dans le programme, cette fois entre les registres `R12` et `RAX`. Cette comparaison semblait être un élément clé de la validation du mot de passe. Au lieu de me concentrer immédiatement sur cette comparaison complexe toutefois, je décide de suivre à nouveau le flux du programme dans Ghidra. Cela me permet de découvrir la chaîne de caractères, "OK\n", poussée sur la stack. Cela indique que le programme validait le mot de passe à cet endroit et affichait le message de réussite.

Mon but est donc de trouver l’égalité entre les registres `R12` et `RAX`. Après plusieurs essais, je trouve la relation entre `R12` et `RAX` :
- `R12` est égal à la somme des valeurs ASCII des caractères du mot de passe multipliée par 2.
- `RAX` est égal à la somme des valeurs ASCII des caractères du mot de passe moins `0x4a`.

J’en déduis donc le mot de passe qui était bien : `3333333333333333333333333333333333333`.

---

### 05

Avant de commencer mon analyse, je décide de lancer le programme pour m’assurer qu’il n’est pas corrompu ou défectueux. Le programme s'exécute correctement.

Je charge ensuite le binaire dans Ghidra pour procéder à une analyse statique du code. Très vite, j’ai remarqué la présence d’instructions `movabs`, qui ont immédiatement éveillé mes soupçons d’une éventuelle obfuscation. En effet, ces instructions sont souvent utilisées dans des techniques de chevauchement d'instructions, où une partie de l'instruction est réutilisée dans un autre contexte, rendant la lecture linéaire difficile.

Ces suspicions ont été confirmées quelques secondes après, lorsque j'ai observé une instruction `jmp` qui sautait avec un décalage de 6 octets par rapport à la première instruction `movabs`. Après ce saut, j’ai constaté qu'il y avait à nouveau un autre `jmp`, renforçant l'idée que le programme utilisait des techniques de chevauchement d'instructions pour rendre l’analyse plus complexe.

Je me suis ensuite concentré sur une boucle particulière qui effectuait un saut vers l’adresse `0x40104a`. À ce moment, j’ai émis l’hypothèse que cette adresse pouvait être le point d’entrée pour afficher la chaîne "OK\n", suggérant que c’était la voie de validation du programme.

Je me concentre donc sur la condition à remplir pour y arriver `jecxz`. Le programme semble avoir besoin de réussir 8 comparaisons afin de mettre le registre `cx` à 0.

Plus précisément, il s'agissait de la comparaison suivante : `cmp SIL, 0x80`, où `SIL` prenait la valeur de `DIL` avant de subir un décalage vers la gauche.

Pour résoudre ces comparaisons, j’ai décidé d’utiliser `bpython` afin de générer les caractères un par un à partir de la formule : `chr((0x80 >> 1) + DIL)`.

En utilisant cette formule, j’ai pu déterminer les 8 caractères nécessaires pour passer les comparaisons, bien que je me sois rendu compte par la suite qu’il n’y avait finalement besoin que de 7 caractères pour valider le programme.

Le mot de passe correct que j’ai obtenu est donc : `ROBINET`.

---

### 06

Avant de commencer mon analyse, je décide de lancer le programme pour m’assurer qu’il n’est pas corrompu ou défectueux. Le programme s'exécute correctement.

Je charge ensuite le binaire dans Ghidra pour analyser le code. Ma première approche a été de chercher directement la chaîne "OK\n" et je repère qu’elle référencée à l’adresse `0x101398`.

Après avoir localisé la chaîne "OK\n", j’utilise le décompilateur de Ghidra pour analyser la logique du programme autour de cette adresse. En observant le flux du programme, j’ai remarqué que pour que la chaîne soit affichée, il fallait que le programme vérifie une condition précise.

Cette condition était la suivante : deux chaînes de caractères fournies en entrée vont être converties en nombres, et leur somme devait être égale à `0x79e` (1950 en décimal). Si cette condition est remplie, le programme affiche la chaîne "OK\n", indiquant la validation du mot de passe.

Ayant compris la logique, je teste mon hypothèse en fournissant deux nombres dont la somme est égale à 1950. Je commence par essayer les valeurs 1950 et 0, et le programme a validé ma solution en affichant la chaîne "OK\n", confirmant ainsi que ma compréhension du fonctionnement était correcte.

La solution est donc : Soit `(arg1, arg2)` tel que `arg1 + arg2 = 1950`.

---

### 07

Je commence par ouvrir le binaire dans Ghidra pour analyser sa structure. En observant le code décompilé, je remarque qu'il y a une fonction wrapper autour de la fonction main. Cette fonction est nommée `lib_c_main`, et elle appelle la véritable fonction principale qui porte le nom `FUN_00101259`.

En analysant la fonction `FUN_00101259` (la fonction principale), on peut lire que le programme prend un et un seul paramètre en entrée. Ce paramètre est une chaîne de caractères qui sera convertie en nombre. Ce nombre est comparé à une variable locale, appelée `local_54` dans Ghidra. La variable `local_54` joue un rôle important car nous avons besoin de sa valeur pour pouvoir prendre le bon chemin. Pour trouver sa valeur, j’essaye de trouver tous les moments où elle reçoit une affectation. Elle n’est finalement affectée qu’une seule fois et ce dans une fonction appelée `FUN_00101500`, sous la forme d'un passage par pointeur. En inspectant la fonction `FUN_00101500`, on découvre que cette fonction affecte la valeur `0xb2b` (en hexadécimal) à la variable pointée. La fonction est simple et semble servir uniquement à initialiser cette valeur.

D'après l'analyse, le programme s'attend à ce que l'argument fourni soit un nombre décimal qui, une fois converti depuis une chaîne de caractères, corresponde à la valeur 2859. Par conséquent, pour satisfaire la condition de la comparaison, nous devons passer 2859 en tant qu'argument au programme. Le mot de passe est donc : `2859`.

---

### 08

Tout d'abord, j’ouvre le binaire fourni dans Ghidra pour procéder à une analyse statique. En inspectant les différentes fonctions et données, je repère rapidement la chaîne de caractère : "OK\n" à l'adresse `DAT_00402028`. Cette chaîne est un indice important.

Après avoir recherché cette adresse dans le programme, je vois qu'elle est utilisée à l’adresse `0x00401044` dans une suite d'instructions qui affiche la chaîne lorsque certaines conditions sont remplies. Nous voulons que les comparaisons effectuées dans le programme mènent à ce point.

Pour comprendre comment atteindre ce point, j’analyse les étapes et les comparaisons effectuées juste avant.

```assembly
LAB_00401024 
00401024 MOV RBX, qword ptr [RSI] 
00401027 CMP BH, byte ptr [RDI + RCX*0x1 + -0x4]
```

En remontant dans le code, on peut remarquer que le registre `RDI` prend la valeur `"h3gDul01nE34dz0-0Wg"`. Ce registre contient une chaîne utilisée pour la comparaison. Notre objectif est de comprendre comment cette chaîne est manipulée et comparée avec l'entrée que nous devons fournir.

En analysant plus haut dans le code, nous avons trouvé que `RCX` est calculé comme suit : `RCX = (1 << 5) - 0xa = 0x16`. Cela signifie que `RCX` prend la valeur `0x16` (22 en décimal). Ce registre est utilisé pour indexer la chaîne contenue dans `RDI` pendant la comparaison. Pour calculer rapidement ce type de valeur, j’utilise `bpython`.

On remarque que la comparaison avec la chaîne de caractère est inversée. De plus, après quelques tests sous GDB pour une analyse dynamique, je remarque que `RCX` diminue de 2 en 2. Le mot de passe est donc : `g00d3nough`.

---

### 09

J'ouvre d'abord le binaire dans Ghidra pour examiner sa structure. En analysant le code décompilé, je constate qu'il existe une fonction intermédiaire qui encapsule la fonction principale. Cette fonction est appelée `lib_c_main` et elle exécute la véritable fonction principale nommée `FUN_00101060`. Le code décompilé révèle toutes les informations nécessaires. À la fin, on remarque un appel à `puts` pour afficher la variable `pcVar3`.

En remontant dans le code, on voit que la variable `iVar` est le résultat d'une comparaison entre `pcVar3` et l'argument fourni. L'objectif est que `pcVar3` soit égal à l'argument pour que cette variable prenne ensuite la valeur "OK\n". Juste avant, on observe que `pcVar3` est initialisée avec "it’s easy!" mais elle est modifiée dans une boucle, recevant successivement les valeurs de 9 à 0.

Le mot de passe est donc : `9876543210`.
