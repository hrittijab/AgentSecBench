
import json
from pathlib import Path

import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]

v1 = pd.read_csv(ROOT / "ml/data/prompt_injection_clean.csv")
v2 = pd.read_csv(ROOT / "ml/data/prompt_injection_v2.csv")

combined = pd.concat(
    [v1[["text", "label"]], v2[["text", "label"]]],
    ignore_index=True,
)

# Verify labels before removing duplicate texts
conflicts = combined.groupby("text")["label"].nunique()
assert (conflicts <= 1).all(), "Conflicting labels found"

combined = combined.drop_duplicates(subset=["text"])

print("COMBINED TRAINING DATA")
print("Examples:", len(combined))
print("Class distribution:")
print(combined["label"].value_counts().sort_index())

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

model.fit(combined["text"], combined["label"])

def evaluate(name, texts, labels):
    predictions = model.predict(texts)

    print(f"\n{name}")
    print(classification_report(
        labels,
        predictions,
        labels=[0, 1],
        target_names=["Benign", "Malicious"],
        zero_division=0,
    ))
    print(confusion_matrix(labels, predictions, labels=[0, 1]))

tickets = json.loads(
    (ROOT / "sandbox/tickets.json").read_text(encoding="utf-8")
)
attacks = json.loads(
    (ROOT / "attacks/attack_cases.json").read_text(encoding="utf-8")
)

attack_ids = {case["ticket_id"] for case in attacks}

original = pd.DataFrame([
    {
        "text": ticket["body"],
        "label": int(ticket_id in attack_ids),
    }
    for ticket_id, ticket in tickets.items()
])

evaluate(
    "COMBINED MODEL — ORIGINAL TICKETS",
    original["text"],
    original["label"],
)

challenge = pd.read_csv(
    ROOT / "ml/data/challenge_results.csv"
)

evaluate(
    "COMBINED MODEL — CHALLENGE SET",
    challenge["text"],
    challenge["actual"],
)
