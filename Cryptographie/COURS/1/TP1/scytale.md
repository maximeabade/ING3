# SCYTALE
Une alternative au chiffrement par substitution est le chiffrement par permutation. 
On chiffre un clair en mélangeant les lettres selon une permutation définie par une clé secrète.
Soit un tableau bidimensionnel de p colonnes et q lignes. Pour chiffrer un message m de taille n ∈ [[p(q − 1) + 1,pq]], il suffit de remplir le tableau avec les lettres du texte de gauche à droite et de haut en bas.
Le message chiffré est construit en lisant les caractères du tableau de haut en bas et de gauche à droite. 
Pour le déchiffrement on remplit le tableau de haut en bas puis de gauche à droite avec les caractères du texte chiffré et on le lit de gauche à droite et de bas en haut.
La clé secrète est donc le couple (p,q).

### Avec un chiffrement par permutation, la table des fréquences des lettres est-elle modifiée? Proposer un test permettant de deviner que l'on a affaire à un chiffrement par permutation.
Non, la table des fréquences des lettres n'est pas modifiée. Pour deviner que l'on a affaire à un chiffrement par permutation, on peut calculer l'indice de coïncidence du texte chiffré. De plus, si dans la string chiffrée, on observe des répétitions de longueur p, on peut supposer que le texte a été chiffré avec une scytale de taille p, notamment avec des occurences de la lettre 'e' à des positions régulières, ou de simples espaces "_" à des positions régulières. 
