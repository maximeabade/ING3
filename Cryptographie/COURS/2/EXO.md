## Retour sur le chiffrement de César

*Démontrer que, si le message ne contient qu'une seule lettre, alors le chiffre de César vu dans le TD1 est parfaitement sécurisé.*

**Réponse** : Si le message ne contient qu'une seule lettre, alors il n'y a qu'une seule possibilité pour le message clair. Il n'y a donc qu'une seule possibilité pour le message chiffré. Le chiffre de César est donc parfaitement sécurisé.

## Retour sur le chiffrement de Vigenère

*Montrer que le chiffrement de Vigenère vu dans le TD1 est parfaitement sécurisé dès lors que la longueur du message n'excède pas celle de la clé. Est-cez toujours le cas si le message est strictement plus long que la clé ?*

**Réponse** : Si la longueur du message n'excède pas celle de la clé, alors le chiffrement de Vigenère est parfaitement sécurisé. En effet, si la longueur du message est inférieure ou égale à celle de la clé, alors le message chiffré est une combinaison linéaire des lettres du message clair. Il n'y a donc qu'une seule possibilité pour le message clair. Il n'y a donc qu'une seule possibilité pour le message chiffré, c'est donc parfaitement sécurisé.

Si le message est strictement plus long que la clé, alors le chiffrement de Vigenère n'est plus sécurisé: si la longueur du message est strictement supérieure à celle de la clé, alors le message chiffré n'est plus une combinaison linéaire des lettres du message clair. Il est alors possible de retrouver le message clair en utilisant une analyse de fréquence.

## One-Time Pad

*Déchiffrez **c=01011101** sachant que la clé est **k=10011011**. Est-ce que le résultat est unique?*

**Réponse** : On a $c = m \oplus k$, donc $m = c \oplus k$. On a donc $m = 01011101 \oplus 10011011 = 11000110$.

Le résultat n'est pas unique, car on peut choisir une autre clé $k'$ telle que $k' = k \oplus 11111111 = 01100100$. On a alors $m = 01011101 \oplus 01100100 = 00111001$.

*Soit M={0,1,2,3}l. Décrire le schéma de chiffrement symétrique OTP dans ce cas. Démontrer qu'il est parfaitement sécurisé (ou pas).*

**Réponse** : Ici on va remplacer le XOR par une addition soustraction modulo 4. On a donc $c = m + k \mod 4$ et $m = c - k \mod 4$. Le chiffrement est parfaitement sécurisé car il n'y a qu'une seule possibilité pour le message clair.

*Combien de temps serait-il possible d'utiliser le chiffre de Vernam pour :*
   - a. l'envoi d'un texte (vitesse d'écriture 40 bits/s) 
   - b. une communication audio (avec encodage audio de 64Kbits/s)
   - c .une communication vidéo en haute résolution (140 Mbits/s)
 
*si ALice et Bob partagent une clé secrète k constituée d'une séquence binaire aléatoire préenregistrée sur :*
   - 1. un CD-R (700 Mo)
   - 2. un DVD (4.7 Go)
   - 3. un Blueray (50 Go)

**Réponse** : On a $t = \frac{N}{v}$, où $N$ est la taille de la clé et $v$ est la vitesse de transmission. On a donc $t = \frac{N}{v}$.
Ainsi l'envoi d'un texte prendrait $t = \frac{N}{40}$, une communication audio prendrait $t = \frac{N}{64000}$ et une communication vidéo en haute résolution prendrait $t = \frac{N}{140000000}$.

Pour un CD-R, on a $N = 700 \times 10^6 \times 8$ bits, pour un DVD on a $N = 4.7 \times 10^9 \times 8$ bits et pour un Blueray on a $N = 50 \times 10^9 \times 8$ bits.

Pour un CD-R, l'envoi d'un texte prendrait $t = \frac{700 \times 10^6 \times 8}{40} = 140000000$ secondes, une communication audio prendrait $t = \frac{700 \times 10^6 \times 8}{64000} = 87500$ secondes et une communication vidéo en haute résolution prendrait $t = \frac{700 \times 10^6 \times 8}{140 \times 10⁶} = 4$ secondes.

Pour un DVD, l'envoi d'un texte prendrait $t = \frac{4.7 \times 10^9 \times 8}{40} = 940000000$ secondes, une communication audio prendrait $t = \frac{4.7 \times 10^9 \times 8}{64000} = 587500$ secondes et une communication vidéo en haute résolution prendrait $t = \frac{4.7 \times 10^9 \times 8}{140 \times 10⁶} = 268,5$ secondes.

Pour un Blueray, l'envoi d'un texte prendrait $t = \frac{50 \times 10^9 \times 8}{40} = 10000000000$ secondes, une communication audio prendrait $t = \frac{50 \times 10^9 \times 8}{64000} = 6250000$ secondes et une communication vidéo en haute résolution prendrait $t = \frac{50 \times 10^9 \times 8}{140 \times 10⁶} = 2857$ secondes.



## One-Time Pad (suite)
*En utilisant le chiffrement One-Time-Pad sur des messages de longueur l avec la clé k = 0l , nous avons c = Enc(k, m) = m; et le message est envoyé en clair ! On suggère donc de modifier le générateur de clés pour que celui-ci ne puisse pas retourner la clé nulle.*

*Décrire la distribution KeyGen selon laquelle sont tirées les clés*

**Réponse** : La distribution KeyGen pour la génération de clés d'un one-time pad (OTP) repose sur la création de clés totalement aléatoires. Chaque bit de la clé est tiré uniformément et indépendamment, avec une probabilité de 50 % d'être un 0 ou un 1. Cela signifie que chaque bit de la clé est choisi de manière aléatoire et imprévisible, garantissant ainsi que la clé n'a aucun biais ou motif identifiable.

Pour que l'OTP soit parfaitement sécurisé, la clé générée doit être aussi longue que le message à chiffrer, et chaque clé ne doit être utilisée qu'une seule fois. De plus, la distribution de cette clé doit être effectuée de manière sécurisée et confidentielle entre les deux parties avant de pouvoir l'utiliser pour chiffrer ou déchiffrer un message.

En résumé, la distribution KeyGen génère des clés en utilisant une source de véritable aléa, où chaque bit a une probabilité égale d'être un 0 ou un 1, garantissant ainsi une clé unique et imprévisible pour chaque message.

*Est-ce vraiment une amélioration du One-Time-Pad? Notamment, le chiffrement est-il toujours parfaitement sécurisé? Justifier votre réponse.*

**Réponse** : 
La modification du générateur de clés pour qu'il ne puisse pas retourner la clé nulle n'améliore pas la sécurité du One-Time-Pad (OTP). En effet, le chiffrement OTP repose sur l'utilisation d'une clé aléatoire de la même longueur que le message à chiffrer. Si la clé est nulle, alors le message chiffré est identique au message en clair, ce qui compromet la sécurité du chiffrement.
Cela dit, en bloquant la génération nulle, on s'assure de correctement chiffrer le message. Cependant, cela ne garantit pas que le chiffrement est parfaitement sécurisé. En effet, le chiffrement OTP est parfaitement sécurisé uniquement si la clé est aléatoire, unique, et utilisée une seule fois. Si la clé est déterministe ou réutilisée, alors le chiffrement n'est plus parfaitement sécurisé.


## One-Time Pad (bonus)

*L’inconvénient majeur du protocole OTP est la difficulté de générer une clé secrète k de taille suffisante et de la communiquer à Alice et à Bob. Alice, débutante en cryptographie, a l’idée suivante pour simplifier la procédure d’échange des clés : au lieu d’une clé aléatoire, elle souhaite utiliser un texte (que Bob possède également). En se mettant d’accord sur la page, ligne et colonne du début du texte à utiliser, elle va ajouter les caractères aux caractères d’un message m, modulo le nombre de caractères dans le texte (on retourne au début du livre lorsque l’on atteint la fin de celui-ci). Est-ce une bonne idée? Justifier votre réponse.*

**Réponse** : 
Pour moi ce n'est pas une bonne idée. En effet ça simplifie l'échange des clés entre Alice et Bob, mais ça compromet également le chiffrement. En effet, si un attaquant intercepte le message chiffré, il peut essayer de retrouver le texte utilisé par Alice et Bob pour générer la clé. En connaissant le texte utilisé, l'attaquant peut alors retrouver la clé et déchiffrer le message. De plus, si le texte utilisé est court ou facilement devinable, alors l'attaquant peut facilement retrouver la clé et déchiffrer le message. En résumé, l'utilisation d'un texte pour générer la clé compromet la sécurité du chiffrement et rend le message vulnérable aux attaques. 
'utilisation de l'aléatoire est selon moi la meilleure solution pour garantir la sécurité du chiffrement.