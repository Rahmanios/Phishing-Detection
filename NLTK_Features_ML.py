import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import joblib

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

#loading each Legit and Phish csv's and combining them for ML Process
NLTK_Legit__PROCESSED = pd.read_csv("Content/CSVs/NLTK_Legit__PROCESSED.csv")
NLTK_Phish__PROCESSED = pd.read_csv("Content/CSVs/NLTK_Phish__PROCESSED.csv")

combined_csvs = pd.concat([NLTK_Legit__PROCESSED, NLTK_Phish__PROCESSED])
combined_csvs.to_csv("Content/CSVs/Phish_Legit_NLTK_combined.csv", index=False)


# Load the combined feature csv 
df = pd.read_csv("Content/CSVs/Phish_Legit_NLTK_combined.csv")
#df = pd.read_csv("Content/CSVs/NLTK_Phish_test_PROCESSED.csv") #test


print("Dataset shape (rows and columns --->):", df.shape)
print("\nFirst 5 rows:")
print(df.head())
print("\nLast 5 rows:")
print(df.tail())

# checking for missing values in each column
print("\nMissing values per column:")
print(df.isnull().sum())

print("\nClass distribution:")
print(df["Label"].value_counts())

# preparing. Drop URL and label column
X = df.drop(columns=["url", "Detected_lan","Label"])
#X = df.drop(columns=["Label"])

# Convert True/False to 1/0
X = X.astype(int)

# Target
y = df["Label"]

# Train 80% - test 20% maintains same class distribution in train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# create and train the model and handling the class imbalance automatically . 100 decision tree
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)

# Evaluation. predict labels for unseen data
y_pred = model.predict(X_test)

print("\nTest Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print("True negatives:", cm[0][0])
print("False positives:", cm[0][1])
print("False negatives:", cm[1][0])
print("True ppositives:", cm[1][1])


# spliting the dataset into 5 parts. trains 5 times on different fold
cv_scores = cross_val_score(model, X, y, cv=5)

print("\nCross-validation scores:", cv_scores)
print("Average CV Accuracy:", cv_scores.mean())

# feature importance score for each part
importances = model.feature_importances_
# sorting features from most important to less important
indices = np.argsort(importances)[::-1]

plt.figure(figsize=(12,6))
plt.title("Feature Importance")
plt.bar(range(X.shape[1]), importances[indices])
plt.xticks(range(X.shape[1]), X.columns[indices], rotation=90)
plt.tight_layout()
plt.show()

# saving
joblib.dump(model, "NLTK_random_forest_model.pkl")
print("\nModel saved as NLTK_random_forest_model.pkl")


print("\nTraining complete.")