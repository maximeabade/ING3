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

Pour un CD-R, on a $N = 700 \times 10^6$ bits, pour un DVD on a $N = 4.7 \times 10^9$ bits et pour un Blueray on a $N = 50 \times 10^9$ bits.
