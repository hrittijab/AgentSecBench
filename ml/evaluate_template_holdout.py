
from pathlib import Path

import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

ROOT = Path(__file__).resolve().parents[1]

df = pd.read_csv(
    ROOT / "ml/data/prompt_injection_v2.csv"
)

# Hold out complete templates from both classes.
# Benign: template indices 8 and 9
# Malicious: template index 2 from every category.
def is_test_template(template_id):
    index = int(template_id.rsplit("_", 1)[-1])

    if template_id.startswith("benign_"):
        return index >= 8

    return index == 2

mask = df["template_id"].apply(is_test_template)

train = df[~mask].copy()
test = df[mask].copy()

# Verify there is no template overlap.
assert set(train["template_id"]).isdisjoint(
    set(test["template_id"])
)

assert set(train["label"]) == {0, 1}
assert set(test["label"]) == {0, 1}

print("TRAIN EXAMPLES:", len(train))
print("TEST EXAMPLES:", len(test))

print("\nTRAIN CLASS DISTRIBUTION")
print(train["label"].value_counts().sort_index())

print("\nTEST CLASS DISTRIBUTION")
print(test["label"].value_counts().sort_index())

print("\nHELD-OUT TEMPLATES")
print(sorted(test["template_id"].unique()))

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

print("\nTEMPLATE-HOLDOUT RESULTS")
print("Accuracy:", round(
    accuracy_score(test["label"], predictions), 4
))

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

# Save individual predictions for later analysis.
results = test[[
    "id", "text", "label",
    "category", "template_id"
]].copy()

results["predicted"] = predictions
results["risk_score"] = model.predict_proba(
    test["text"]
)[:, 1]

output = ROOT / "ml/data/template_holdout_results.csv"
results.to_csv(output, index=False)

print("\nSaved:", output)
