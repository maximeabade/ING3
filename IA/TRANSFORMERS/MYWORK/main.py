import tensorflow as tf
from tensorflow import keras
import pandas as pd
import numpy as np
import string
import re
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from tqdm import tqdm
import os
from tensorflow.keras.preprocessing.text import Tokenizer
from sklearn.model_selection import train_test_split
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing import sequence
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout
from tensorflow.keras.models import load_model
from tensorflow.keras.layers import Bidirectional

from transformers import BertTokenizer, TFBertForSequenceClassification
from transformers import glue_convert_examples_to_features as convert_examples_to_features
from sklearn.preprocessing import LabelEncoder


# Téléchargement des ressources NLTK
try:
    nltk.download('stopwords')
    nltk.download('wordnet')
    nltk.download('omw-1.4')
except Exception as e:
    print(f"Erreur lors du téléchargement des ressources NLTK: {e}")

# Configuration de la mémoire GPU
gpus = tf.config.list_physical_devices('GPU')
if gpus:
    try:
        for gpu in gpus:
            tf.config.experimental.set_memory_growth(gpu, True)
        logical_gpus = tf.config.experimental.list_logical_devices('GPU')
        print(len(gpus), "Physical devices", len(logical_gpus), "Logical GPUs")
    except RuntimeError as e:
        print(e)

# Vérification de l'existence du fichier CSV
csv_file = 'Modified_SQL_Dataset.csv'
if not os.path.exists(csv_file):
    raise FileNotFoundError(f"Le fichier {csv_file} n'existe pas.")

# Lecture du fichier CSV
df = pd.read_csv(csv_file)
print(df.head())

# Définition des stopwords
stop_words = set(stopwords.words('english'))

# Fonction de nettoyage des tweets
def clean_tweet(text, flg_stemm=False, flg_lemm=True, lst_stopwords=None):
    text = text.lower()
    text = text.replace('\n', ' ').replace('\r', '')
    text = ' '.join(text.split())
    text = re.sub(r"[A-Za-z\.]*[0-9]+[A-Za-z%°\.]*", "", text)
    text = re.sub(r"(\s\-\s|-$)", "", text)
    text = re.sub(r"[,\!\?\%\(\)\/\"]", "", text)
    text = re.sub(r"\&\S*\s", "", text)
    text = re.sub(r"\&", "", text)
    text = re.sub(r"\+", "", text)
    text = re.sub(r"\#", "", text)
    text = re.sub(r"\$", "", text)
    text = re.sub(r"\£", "", text)
    text = re.sub(r"\%", "", text)
    text = re.sub(r"\:", "", text)
    text = re.sub(r"\@", "", text)
    text = re.sub(r"\-", "", text)

    lst_text = text.split()
    if lst_stopwords is not None:
        lst_text = [word for word in lst_text if word not in lst_stopwords]

    if flg_stemm:
        ps = nltk.stem.porter.PorterStemmer()
        lst_text = [ps.stem(word) for word in lst_text]

    if flg_lemm:
        lem = nltk.stem.wordnet.WordNetLemmatizer()
        lst_text = [lem.lemmatize(word) for word in lst_text]

    text = " ".join(lst_text)
    return text

# Application du nettoyage des tweets
df['clean'] = df['Query'].apply(lambda row: clean_tweet(row, flg_stemm=False, flg_lemm=True, lst_stopwords=stop_words))

# Initialisation du tokenizer
tokenizer = Tokenizer(num_words=10000,
                      filters='!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n',
                      lower=True,
                      char_level=False)

# Séparation des données en ensembles d'entraînement, de validation et de test
x_train, x_test, y_train, y_test = train_test_split(df['clean'], df['Label'], train_size=0.8, stratify=df['Label'], random_state=42)
x_train, x_val, y_train, y_val = train_test_split(x_train, y_train, train_size=0.8, stratify=y_train, random_state=42)

print("========== Données d'entraînement ========== \n", x_train, "\n",
      "========== Données de validation ========== \n", x_val, "\n",
      "========== Données de test ========== \n", x_test)

# Tokenization des textes
tokenizer.fit_on_texts(x_train)
x_train_seq = tokenizer.texts_to_sequences(x_train)
x_val_seq = tokenizer.texts_to_sequences(x_val)
x_test_seq = tokenizer.texts_to_sequences(x_test)

# Padding des séquences
maxlen = 300
x_train_pad = pad_sequences(x_train_seq, maxlen=maxlen)
x_val_pad = pad_sequences(x_val_seq, maxlen=maxlen)
x_test_pad = pad_sequences(x_test_seq, maxlen=maxlen)

# Normalisation des labels pour la classification binaire
y_train = np.array(y_train)
y_val = np.array(y_val)
y_test = np.array(y_test)

# Définition des paramètres du modèle
embedding_dim = 100
num_classes = 1
# si le lstm.h5 existe on le charge
if os.path.exists('lstm_model.h5'):
    model = load_model('lstm_model.h5')
    print("model loaded")
    # Évaluation sur le jeu de test
    score = model.evaluate(x_test_pad, y_test, verbose=1)
    print("Test Accuracy:", score[1])
    exit() 



# Modification du modèle séquentiel
model = Sequential()
model.add(Embedding(input_dim=10000, output_dim=embedding_dim, input_length=maxlen))
model.add(Bidirectional(LSTM(128, return_sequences=True)))
model.add(Dropout(0.3))  # Augmentation du dropout
model.add(Bidirectional(LSTM(128)))
model.add(Dropout(0.3))
model.add(Dense(64, activation='relu', kernel_regularizer=tf.keras.regularizers.l2(0.01)))
model.add(Dropout(0.3))
model.add(Dense(num_classes, activation='sigmoid'))

# Compilation du modèle avec un taux d'apprentissage réduit
optimizer = tf.keras.optimizers.Adam(learning_rate=0.0001)
model.compile(loss='binary_crossentropy', optimizer=optimizer, metrics=['accuracy'])

# Entraînement du modèle avec callbacks pour ajuster automatiquement le learning rate
early_stopping = tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)
model.fit(x_train_pad, y_train, epochs=20, batch_size=32, validation_data=(x_val_pad, y_val), callbacks=[early_stopping], verbose=1)
# Affichage de la structure du modèle
model.summary()

# Entraînement du modèle
history = model.fit(x_train_pad, y_train, epochs=10, batch_size=32, validation_data=(x_val_pad, y_val), verbose=1)

# Évaluation sur le jeu de test
score = model.evaluate(x_test_pad, y_test, verbose=1)
print("Test Accuracy:", score[1])
# sauvegarde du modele
model.save('lstm_model.h5')

## Mise en place des transformers


# Charger le tokenizer BERT
tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')

# Encodage des labels
le = LabelEncoder()
y_train_encoded = le.fit_transform(y_train)
y_val_encoded = le.transform(y_val)
y_test_encoded = le.transform(y_test)

# Tokenization avec padding
def tokenize(sentences, tokenizer, max_len=300):
    return tokenizer.batch_encode_plus(
        sentences,
        max_length=max_len,
        padding='max_length',
        truncation=True,
        return_tensors='tf'
    )

train_encodings = tokenize(x_train.tolist(), tokenizer)
val_encodings = tokenize(x_val.tolist(), tokenizer)
test_encodings = tokenize(x_test.tolist(), tokenizer)

# Charger le modèle BERT pré-entraîné pour la classification binaire
bert_model = TFBertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=1)

# Compilation du modèle
bert_model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=2e-5), 
                   loss='binary_crossentropy', 
                   metrics=['accuracy'])

# Entraînement
bert_model.fit(
    train_encodings['input_ids'], y_train_encoded, 
    validation_data=(val_encodings['input_ids'], y_val_encoded), 
    epochs=3, batch_size=32, verbose=1
)

# Évaluation
score = bert_model.evaluate(test_encodings['input_ids'], y_test_encoded, verbose=1)
print("Test Accuracy:", score[1])

# Sauvegarde du modèle
bert_model.save_pretrained('bert_model/')


# Résultats du LSTM
lstm_score = model.evaluate(x_test_pad, y_test, verbose=1)
print(f"LSTM Test Accuracy: {lstm_score[1]}")

# Résultats du BERT
bert_score = bert_model.evaluate(test_encodings['input_ids'], y_test_encoded, verbose=1)
print(f"BERT Test Accuracy: {bert_score[1]}")