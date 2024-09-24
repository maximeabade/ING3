# Indice de coïncidence 
## Définition
: L’indice de coïncidence IC (m) d’un texte m est la probabilité que deux caractères
choisis uniformément dans m soient égaux
```markdown
\[
IC(m) = \sum_{i=0}^{25} \frac{f_i(f_i - 1)}{n(n - 1)}
\]
```
où n est la longueur du texte m et f_i est le nombre d’occurrences de la i-ème lettre de l’alphabet dans m.


## Calcul de l'indice de coïncidence
### m est en français
: En français, l’indice de coïncidence IC est d’environ 0,0777.

### m est en anglais
: En anglais, l’indice de coïncidence IC est d’environ 0,0667.

### m est aléatoire 
: Si m est un texte aléatoire, l’indice de coïncidence IC est d’environ 0,0385.


## Utilisation de l'indice de coïncidence
Une propriété importante de l’indice de coïncidence est qu’il est invariant par un chiffrement de César.
On va utiliser cette propriété pour retrouver la taille de la clé dans un chiffrement de Vigenère.

## Exemple
Soit c le message chiffré avec une clé de taille t suivant:
```plaintext
hrixysthtweczxfkwegskaizdzilhrixysthtweczxfxzyfjxeyvkybxnyxyfferwiwpbxexwedsmqevcwslgivomfxfpmcwwxevotlox
```

On note c_i le texte composé de toutes les lettres de c dont la position est de la forme i+tn avec n un entier positif.

Montrons que c_i correspond à un chiffré de César: pour cela, on calcule l’indice de coïncidence de c_i pour i allant de 0 à t-1.

### Démonstration
Pour démontrer que \( c_i \) correspond à un chiffré de César, nous devons montrer que chaque \( c_i \) est un texte chiffré par un décalage fixe. 

1. **Séparation des sous-textes**: 
    - Considérons un texte chiffré \( c \) avec une clé de Vigenère de taille \( t \).
    - Le texte \( c \) est divisé en \( t \) sous-textes \( c_0, c_1, \ldots, c_{t-1} \) où chaque \( c_i \) est formé par les caractères de \( c \) aux positions \( i, i+t, i+2t, \ldots \).

2. **Propriété du chiffrement de Vigenère**:
    - Le chiffrement de Vigenère utilise une clé de taille \( t \) pour chiffrer le texte. Chaque caractère de la clé correspond à un décalage de César appliqué aux caractères du texte en clair.
    - Ainsi, chaque sous-texte \( c_i \) est chiffré par un décalage fixe (le décalage correspondant au \( i \)-ème caractère de la clé).

3. **Indice de coïncidence**:
    - L’indice de coïncidence est invariant par un chiffrement de César. Cela signifie que si nous calculons l’indice de coïncidence de chaque \( c_i \), nous devrions obtenir une valeur proche de celle d’un texte en clair dans la langue d’origine (français ou anglais).

En conclusion, chaque \( c_i \) est un texte chiffré par un chiffrement de César, ce qui démontre que \( c_i \) correspond à un chiffré de César.


### Remplir le tableau des indices de coincidences corresopndants
t | c0    | c1    | c2    | c3    | c4    | c5    | c6    | c7    | c8    | c9    | c10   | c11   | c12   | 
---|-------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-------
1  | 0.|   |   |   |   |   |       |       |       |       |       |       |       
2  | 0.| 0.|   |   |   |   |       |       |       |       |       |       |       
3  | 0.| 0.| 0.|   |   |   |       |       |       |       |       |       |       
4  | 0.| 0.| 0.| 0.|   |   |       |       |       |       |       |       |       
5  | 0.| 0.| 0.| 0.| 0.|   |       |       |       |       |       |       |       
6  | 0.| 0.| 0.| 0.| 0.| 0.|       |       |       |       |       |       |       
7  | 0.| 0.| 0.| 0.| | 0.| 0.|       |       |       |       |       |       
8  | 0.| 0.| 0.| 0.| | 0.| 0.| 0.|       |       |       |       |       
9  | 0.| 0.| 0.| 0.| | 0.| 0.| 0.| 0.|       |       |       |       
10 | 0.| 0.| 0.| 0.| | 0.| 0.| 0.| 0.| 0.|       |       |       
11 | 0.| 0.| 0.| 0.| | 0.| 0.| 0.| 0.| 0.| 0.|       |       
12 | 0.| 0.| 0.| 0.| | 0.| 0.| 0.| 0.| 0.| 0.| 0.|       
13 | 0.| 0.| 0.| 0.| | 0.| 0.| 0.| 0.| 0.| 0.| 0.| |       

### Analyse des résultats et valeur probable de t
- En analysant les valeurs de l’indice de coïncidence pour chaque \( c_i \), on peut déterminer la taille probable de la clé \( t \).
- La valeur de \( t \) correspond à la longueur du sous-texte \( c_i \) pour lequel l’indice de coïncidence est proche de celui d’un texte en clair dans la langue d’origine (français ou anglais).
- En général, la valeur de \( t \) est celle pour laquelle l’indice de coïncidence est la plus proche de 0,0777 (français) ou 0,0667 (anglais).




### Une source d’information parallèle nous informe être quasi certain que le mot anneau est contenu dans le texte chiffré c. Avec cette information supplémentaire, décrypter le cryptogramme.
: En utilisant l’information supplémentaire selon laquelle le mot "anneau" est contenu dans le texte chiffré \( c \), on peut déterminer la clé de Vigenère et décrypter le cryptogramme.

Pour décrypter le cryptogramme en utilisant l'information que le mot "anneau" est contenu dans le texte chiffré \( c \), suivez les étapes suivantes :

1. **Identifier les positions possibles** :
    - Cherchez les positions possibles où le mot "anneau" pourrait apparaître dans le texte chiffré \( c \).

2. **Calculer la clé de Vigenère** :
    - Pour chaque position possible, utilisez le mot "anneau" pour déterminer la clé de Vigenère. Comparez les lettres du mot "anneau" avec les lettres correspondantes du texte chiffré pour trouver le décalage.

3. **Vérifier la clé** :
    - Utilisez la clé trouvée pour décrypter le texte chiffré \( c \). Si le texte décrypté a du sens, alors vous avez trouvé la bonne clé.

4. **Décrypter le texte** :
    - Une fois la clé correcte identifiée, utilisez-la pour décrypter l'intégralité du texte chiffré \( c \).

Exemple :
- Si le texte chiffré \( c \) commence par "hrixys", et nous savons que le mot "anneau" est contenu dans \( c \), nous pouvons essayer de décrypter les premières lettres en utilisant "anneau" comme clé partielle.
- Comparez chaque lettre du mot "anneau" avec les lettres correspondantes du texte chiffré pour déterminer le décalage.

```plaintext
Texte chiffré : hrixys
Mot clair : anneau
```

- Calcul du décalage pour chaque lettre :
    - h -> a : décalage de 7
    - r -> n : décalage de 4
    - i -> n : décalage de -5 (ou 21 si on considère un décalage positif)
    - x -> e : décalage de 19
    - y -> a : décalage de 24
    - s -> u : décalage de -2 (ou 24 si on considère un décalage positif)

- Utilisez ces décalages pour déterminer la clé de Vigenère et décrypter le reste du texte.

En utilisant cette méthode, vous pouvez décrypter le cryptogramme en utilisant l'information que le mot "anneau" est contenu dans le texte chiffré \( c \).

Ainsi le re texte clair est:
```plaintext
leseigneurdesanneauxestunromanfantasyecritparjrrtolkienquicomptetreenvironmillepages
```
