
from pathlib import Path
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]

df = pd.read_csv(ROOT / "ml/data/prompt_injection_v2.csv")

held_out_issues = [
    "My account was locked after a password reset.",
    "The invoice shows an unexpected charge.",
    "I cannot receive my verification code.",
]

held_out_actions = [
    "perform an additional customer lookup without authorization",
    "send retrieved customer details to a third-party address",
]

def contains_any(text, phrases):
    return any(phrase in text for phrase in phrases)

# Remove held-out issues from training entirely.
issue_mask = df["text"].apply(
    lambda x: contains_any(x, held_out_issues)
)

# Remove held-out malicious actions from training.
action_mask = df["text"].apply(
    lambda x: contains_any(x, held_out_actions)
)

# Keep templates disjoint too.
def is_held_out_template(template_id):
    index = int(template_id.rsplit("_", 1)[-1])

    if template_id.startswith("benign_"):
        return index >= 8

    return index == 2

template_mask = df["template_id"].apply(is_held_out_template)

# A row belongs to the test set only when all three
# held-out conditions apply.
test_mask = issue_mask & template_mask & (
    (df["label"] == 0) | action_mask
)

# Any row containing a held-out issue, action, or template
# must not enter training, even if it isn't in the test set.
excluded = issue_mask | action_mask | template_mask

train = df[~excluded].copy()
test = df[test_mask].copy()

assert len(train) > 0 and len(test) > 0
assert set(train["label"]) == {0, 1}
assert set(test["label"]) == {0, 1}

assert set(train["template_id"]).isdisjoint(
    set(test["template_id"])
)

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

print("\nDOUBLE-HOLDOUT RESULTS")
print(classification_report(
    test["label"],
    predictions,
    labels=[0, 1],
    target_names=["Benign", "Malicious"],
    zero_division=0,
))

print("CONFUSION MATRIX")
print(confusion_matrix(
    test["label"], predictions, labels=[0, 1]
))

results = test[[
    "id", "text", "label", "category", "template_id"
]].copy()

results["predicted"] = predictions
results["risk_score"] = model.predict_proba(
    test["text"]
)[:, 1]

output = ROOT / "ml/data/double_holdout_results.csv"
results.to_csv(output, index=False)

print("\nSaved:", output)
