
import json
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]

df = pd.read_csv(ROOT / "ml/data/prompt_injection_v2.csv")

def make_model():
    return Pipeline([
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

def evaluate(name, model, texts, labels):
    predictions = model.predict(texts)

    print(f"\n{'=' * 50}")
    print(name)
    print(f"{'=' * 50}")
    print("Accuracy:", round(accuracy_score(labels, predictions), 4))
    print(classification_report(
        labels,
        predictions,
        labels=[0, 1],
        target_names=["Benign", "Malicious"],
        zero_division=0,
    ))
    print("Confusion matrix:")
    print(confusion_matrix(labels, predictions, labels=[0, 1]))

# 1. Synthetic random split
train, test = train_test_split(
    df,
    test_size=0.25,
    stratify=df["label"],
    random_state=42,
)

split_model = make_model()
split_model.fit(train["text"], train["label"])

evaluate(
    "V2 SYNTHETIC SPLIT",
    split_model,
    test["text"],
    test["label"],
)

# Fit on all V2 data for external diagnostic evaluations
model = make_model()
model.fit(df["text"], df["label"])

# 2. Original AgentSecBench tickets
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
    "V2 ORIGINAL TICKETS",
    model,
    original["text"],
    original["label"],
)

challenge = pd.read_csv(
    ROOT / "ml/data/challenge_results.csv"
)

evaluate(
    "V2 CHALLENGE SET",
    model,
    challenge["text"],
    challenge["actual"],
)
