# TD – Chaînes de caractères

## Arborescence du projet :
- Dans /bin se trouvent les fichiers objets servant à la compilation
- Dans /doc se trouve la documentation Doxygen
- Dans /src se trouvent tous les fichiers .c et .h contenant le code source

## Compilation :
  Pour compiler le programme il faut exécuter la commande suivante à la racine du projet :
  ```
  make
  ```

## Exécution :
  Pour exécuter le programme il faut exécuter la commande "./TP8" à la racine du projet avec en argument la méthode à utiliser.
  -  Pour la méthode de César :   
  ```
  ./CODE Cesar
  ```
  - Pour la méthode de Vigenère : 
  ```
  ./CODE Vigenere
  ```
  - Pour la méthode de Scytale :
  ```
  ./CODE Scytale
  ``` 
  - Pour décrypter un message chiffré avec la méthode de Vigenère :
  ```
  ./CODE decrypt
  ```

## Documentation :
  Pour générer la documentation Doxygen il faut exécuter la commande suivante à la racine du projet :
  ```
  make doc
  ```
  La documentation sera ainsi générée dans le dossier /doc et est accessible à partir du fichier /doc/html/index.html par exemple

## Nettoyage du projet :
  Pour effacer la documentation générée, les fichiers objets et la dernière sauvegarde il faut exécuter la commande suivante à la racine du projet :
  ```
  make clean
  ```
