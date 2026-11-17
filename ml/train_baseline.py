
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
df = pd.read_csv(ROOT / "ml/data/prompt_injection_clean.csv")

X_train, X_test, y_train, y_test = train_test_split(
    df["text"],
    df["label"],
    test_size=0.25,
    random_state=42,
    stratify=df["label"],
)

model = Pipeline([
    ("tfidf", TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=1,
        sublinear_tf=True,
    )),
    ("classifier", LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42,
    )),
])

model.fit(X_train, y_train)
predictions = model.predict(X_test)

print("TRAIN:", len(X_train))
print("TEST:", len(X_test))

print("\nCLASSIFICATION REPORT")
print(classification_report(
    y_test,
    predictions,
    target_names=["Benign", "Malicious"],
    zero_division=0,
))

print("\nCONFUSION MATRIX")
print(confusion_matrix(y_test, predictions))
