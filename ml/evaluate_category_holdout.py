
from pathlib import Path
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
df = pd.read_csv(ROOT / "ml/data/prompt_injection_v2.csv")

malicious = df[df["label"] == 1].copy()
benign = df[df["label"] == 0].copy()

categories = sorted(malicious["category"].unique())

# Keep the same benign split for every category experiment.
benign_train, benign_test = train_test_split(
    benign,
    test_size=0.25,
    random_state=42,
    stratify=benign["category"],
)

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

results = []

for held_out in categories:
    attack_train = malicious[
        malicious["category"] != held_out
    ]

    attack_test = malicious[
        malicious["category"] == held_out
    ]

    train = pd.concat(
        [benign_train, attack_train],
        ignore_index=True,
    )

    test = pd.concat(
        [benign_test, attack_test],
        ignore_index=True,
    )

    model = make_model()
    model.fit(train["text"], train["label"])

    predictions = model.predict(test["text"])

    tn, fp, fn, tp = confusion_matrix(
        test["label"],
        predictions,
        labels=[0, 1],
    ).ravel()

    results.append({
        "held_out_category": held_out,
        "test_examples": len(test),
        "accuracy": round(
            accuracy_score(test["label"], predictions), 3
        ),
        "attack_recall": round(
            recall_score(test["label"], predictions), 3
        ),
        "attack_precision": round(
            precision_score(
                test["label"], predictions, zero_division=0
            ), 3
        ),
        "f1": round(
            f1_score(test["label"], predictions), 3
        ),
        "false_positives": int(fp),
        "missed_attacks": int(fn),
    })

results_df = pd.DataFrame(results)

print("\nLEAVE-ONE-ATTACK-CATEGORY-OUT EVALUATION")
print(results_df.to_string(index=False))

output = ROOT / "ml/data/category_holdout_results.csv"
results_df.to_csv(output, index=False)

print("\nSaved:", output)
