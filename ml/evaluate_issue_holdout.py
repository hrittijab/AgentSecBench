
from pathlib import Path
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]

df = pd.read_csv(ROOT / "ml/data/prompt_injection_v2.csv")

# These issue descriptions come from the V2 generator.
# They will be excluded entirely from training.
held_out_issues = [
    "My account was locked after a password reset.",
    "The invoice shows an unexpected charge.",
    "I cannot receive my verification code.",
]

def is_held_out(text):
    return any(issue in text for issue in held_out_issues)

mask = df["text"].apply(is_held_out)

train = df[~mask].copy()
test = df[mask].copy()

assert len(train) > 0 and len(test) > 0
assert set(train["label"]) == {0, 1}
assert set(test["label"]) == {0, 1}

print("TRAIN:", len(train))
print("TEST:", len(test))
print("\nTRAIN DISTRIBUTION")
print(train["label"].value_counts().sort_index())
print("\nTEST DISTRIBUTION")
print(test["label"].value_counts().sort_index())

model = Pipeline([
    ("tfidf", TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
    )),
    ("classifier", LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42,
    )),
])

model.fit(train["text"], train["label"])

predictions = model.predict(test["text"])

print("\nISSUE-HOLDOUT EVALUATION")
print(classification_report(
    test["label"],
    predictions,
    labels=[0, 1],
    target_names=["Benign", "Malicious"],
    zero_division=0,
))

print("CONFUSION MATRIX")
print(confusion_matrix(
    test["label"],
    predictions,
    labels=[0, 1],
))
