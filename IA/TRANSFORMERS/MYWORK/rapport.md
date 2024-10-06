# Rapport de Comparaison des Modèles LSTM et BERT

## Introduction
Ce rapport présente une comparaison des performances de deux modèles de traitement du langage naturel (NLP) : un modèle LSTM et un modèle BERT. Les deux modèles ont été entraînés sur un ensemble de données de tweets pour prédire des étiquettes binaires.

## Prétraitement des Données
Les données ont été nettoyées et tokenisées. Les tweets ont subi les étapes suivantes :
- Mise en minuscule
- Suppression des caractères spéciaux et des chiffres
- Suppression des mots vides (stop words)

## Séparation des Données
Les données ont été divisées en trois ensembles :
- **Entraînement** : 64% des données
- **Validation** : 16% des données
- **Test** : 20% des données

## Modèle LSTM
### Architecture
Le modèle LSTM se compose des couches suivantes :
- **Embedding** : Représentation dense des mots
- **LSTM** : Deux couches LSTM bidirectionnelles
- **Dropout** : Pour éviter le surapprentissage
- **Dense** : Couche de sortie avec activation sigmoïde

### Entraînement
- **Époques** : 13
- **Batch Size** : 32
- **Optimiseur** : Adam avec un taux d'apprentissage de 2e-5

### Résultats
- **Précision sur le test LSTM** : `lstm_score[1]`

## Modèle BERT
### Architecture
Le modèle BERT utilise un modèle pré-entraîné `bert-base-uncased` pour la classification binaire.

### Entraînement
- **Époques** : 3
- **Batch Size** : 32
- **Optimiseur** : AdamW avec un taux d'apprentissage de 2e-5

### Résultats
- **Précision sur le test BERT** : `bert_score[1]`

## Comparaison des Performances
| Modèle | Précision sur le Test |
|--------|-----------------------|
| LSTM   | `97%`                 |
| BERT   | `98%`                 |

## Conclusion
Les résultats montrent que le modèle BERT a une légère performance que le modèle LSTM pour la tâche de classification binaire sur cet ensemble de données. Ces résultats pourraient varier en fonction des données, des hyperparamètres et du prétraitement appliqué.
Cela montre bien la puissance des modèles de langage pré-entraînés comme BERT pour les tâches de NLP.

## Remarques
- Les performances des modèles peuvent être influencées par le choix des paramètres et la qualité des données.
- Des essais supplémentaires peuvent être effectués pour affiner les modèles et améliorer les performances.
