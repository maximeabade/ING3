import pandas as pd
import numpy as np # type: ignore
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.linear_model import Lasso
from sklearn.metrics import accuracy_score, mean_squared_error
from xgboost import XGBClassifier
import shap
from tensorflow.keras.models import Sequential # type: ignore
from tensorflow.keras.layers import Dense #type: ignore
import tensorflow as tf
from scipy.stats import uniform

# Charger les données
df = pd.read_csv('file_pe_headers.csv')

# Échantillonner les données pour ACP et clustering (accélérer le processus)
sample_size = 1000 if len(df) > 1000 else len(df)
df_sample = df.sample(sample_size, random_state=42)

X = df_sample.drop(["Name", "Malware"], axis=1).to_numpy()
y = df_sample["Malware"]

# Prétraitement des données
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Réduction de dimensions avec ACP (avec échantillon)
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)

plt.figure(figsize=(10, 7))
plt.scatter(X_pca[:, 0], X_pca[:, 1], c=y, cmap='viridis', edgecolor='k', s=50)
plt.xlabel('Composante principale 1')
plt.ylabel('Composante principale 2')
plt.title('ACP (échantillon)')
plt.colorbar(label='Malware')
plt.show()

# Clustering avec KMeans (toujours sur échantillon)
kmeans = KMeans(n_clusters=2, random_state=42)
clusters = kmeans.fit_predict(X_scaled)

plt.figure(figsize=(10, 7))
plt.scatter(X_pca[:, 0], X_pca[:, 1], c=clusters, cmap='viridis', edgecolor='k', s=50)
plt.xlabel('Composante principale 1')
plt.ylabel('Composante principale 2')
plt.title('Clustering KMeans (échantillon)')
plt.colorbar(label='Cluster')
plt.show()

# Préparation des données pour l'entraînement des modèles
X = df.drop(["Name", "Malware"], axis=1).to_numpy()
y = df["Malware"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Modèle 1 : Régression Lasso avec RandomizedSearchCV
lasso = Lasso()
param_distributions = {'alpha': uniform(0.01, 100)}  # Distribution uniforme pour éviter de tester chaque alpha

lasso_random = RandomizedSearchCV(lasso, param_distributions, n_iter=20, cv=5, random_state=42)
lasso_random.fit(X_train, y_train)
lasso_best = lasso_random.best_estimator_
lasso_pred = lasso_best.predict(X_test)

lasso_mse = mean_squared_error(y_test, lasso_pred)
print(f"Meilleur modèle Lasso avec alpha={lasso_random.best_params_['alpha']}, MSE: {lasso_mse}")

# Modèle 2 : XGBoost avec SHAP
XGB_model = XGBClassifier(use_label_encoder=False, eval_metric='logloss')  # Eviter les avertissements inutiles
XGB_model.fit(X_train, y_train)
y_test_pred = XGB_model.predict(X_test)

accuracy = accuracy_score(y_test, y_test_pred)
print(f"Accuracy XGBoost: {accuracy * 100:.2f}%")

# Importance des features avec SHAP (accélérer en ne prenant que des échantillons si trop lent)
explainer = shap.Explainer(XGB_model, X_test[:100])  # Accélération en limitant les échantillons
shap_values = explainer(X_test[:100])

shap.summary_plot(shap_values, X_test[:100])  # Plot d'importance des features

# Modèle 3 : Réseau fully-connect (avec réduction du nombre d'époques)
# Détection GPU pour accélérer le processus
physical_devices = tf.config.list_physical_devices('GPU')
if physical_devices:
    tf.config.experimental.set_memory_growth(physical_devices[0], True)

model = Sequential()
model.add(Dense(128, input_dim=X_train.shape[1], activation='relu'))
model.add(Dense(64, activation='relu'))
model.add(Dense(1, activation='sigmoid'))

model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

# Réduire le nombre d'époques pour accélérer l'entraînement
history = model.fit(X_train, y_train, epochs=50, batch_size=128, validation_data=(X_test, y_test))  # Passé de 150 à 50

# Évaluation du modèle
loss, accuracy = model.evaluate(X_test, y_test)
print(f"Accuracy Réseau Fully-Connect: {accuracy * 100:.2f}%")

# Comparaison des modèles
print("\nComparaison des modèles:")
print(f"Lasso: MSE = {lasso_mse}")
print(f"XGBoost: Accuracy = {accuracy_score(y_test, y_test_pred) * 100:.2f}%")
print(f"Réseau Fully-Connect: Accuracy = {accuracy * 100:.2f}%")
