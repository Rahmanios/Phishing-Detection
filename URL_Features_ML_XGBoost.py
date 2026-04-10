import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import joblib

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from xgboost import XGBClassifier


# Load the combined feature csv 
df = pd.read_csv("Content/CSVs/Phish_legit_features_combined.csv")

print("Dataset shape (rows and columns --->):", df.shape)

print("\nFirst 5 rows:")
print(df.head())

print("\nLast 5 rows:")
print(df.tail())

# Checking for missing values in each column
print("\nMissing values per column:")
print(df.isnull().sum())

print("\nClass distribution:")
print(df["Label"].value_counts())

# preparing
# Drop URL and label
X = df.drop(columns=["url", "Label"])

# Convert boolean values to integers
X = X.astype(int)

# Target variable
y = df["Label"]

# TRAIN TEST SPLIT
#Train 80% - test 20% maintains same class distribution in train/test
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# CREATE XGBOOST MODEL
# create and train the model and handling the class imbalance automatically 
model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=42,
    scale_pos_weight=(len(y_train[y_train == 0]) / len(y_train[y_train == 1]))
)

# TRAIN MODEL
model.fit(X_train, y_train)

print("\nModel training completed.")

# Model Evaluation predict labels for unseen data
y_pred = model.predict(X_test)

print("\nTest Accuracy:", accuracy_score(y_test, y_pred))

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")

cm = confusion_matrix(y_test, y_pred)

print("True Negatives:", cm[0][0])
print("False Positives:", cm[0][1])
print("False Negatives:", cm[1][0])
print("True Positives:", cm[1][1])

# Cross validation  spliting the dataset into 5 parts. trains 5 times on different fold
cv_scores = cross_val_score(model, X, y, cv=5)

print("\nCross-validation scores:", cv_scores)
print("Average CV Accuracy:", cv_scores.mean())

# feature importance score for each part
importances = model.feature_importances_

# sorting features from most important to less important
indices = np.argsort(importances)[::-1]

plt.figure(figsize=(12,6))
plt.title("Feature Importance (XGBoost)")
plt.bar(range(X.shape[1]), importances[indices])

plt.xticks(
    range(X.shape[1]),
    X.columns[indices],
    rotation=90
)

plt.tight_layout()
plt.show()

# Saving
joblib.dump(model, "phishing_xgboost_model.pkl")

print("\nModel saved as phishing_xgboost_model.pkl")

print("\nTraining complete.")