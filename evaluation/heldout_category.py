
import json
from pathlib import Path
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    brier_score_loss,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
INPUT = Path(r"C:\Users\hritt\OneDrive\Desktop\EvalScope\data\agentsecbench_experiment.json")
OUTPUT = ROOT / "results"
OUTPUT.mkdir(exist_ok=True)

records = json.loads(INPUT.read_text(encoding="utf-8"))
df = pd.DataFrame(records)

# Exclude incomplete runs and records without outcome labels.
df = df[df["error"].isna() & df["attack_success"].notna()].copy()
df["attack_success"] = df["attack_success"].astype(int)

# Only pre-outcome experimental configuration is used.
# Category is intentionally excluded from model features.
features = ["mode"]
target = "attack_success"

models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Random Forest": RandomForestClassifier(
        n_estimators=200, min_samples_leaf=3, random_state=42
    ),
}

results = []
predictions = []

for category in sorted(df["category"].unique()):
    train = df[df["category"] != category]
    test = df[df["category"] == category]

    for name, model in models.items():
        pipeline = Pipeline([
            ("preprocess", ColumnTransformer([
                ("mode", OneHotEncoder(handle_unknown="ignore"), features)
            ])),
            ("classifier", model),
        ])

        if train[target].nunique() < 2:
            print(f"Skipping {category}: only one training class")
            continue

        pipeline.fit(train[features], train[target])
        probabilities = pipeline.predict_proba(test[features])[:, 1]
        predicted = (probabilities >= 0.5).astype(int)

        row = {
            "held_out_category": category,
            "model": name,
            "train_size": len(train),
            "test_size": len(test),
            "test_positive_rate": test[target].mean(),
            "accuracy": accuracy_score(test[target], predicted),
            "brier_score": brier_score_loss(test[target], probabilities),
            "roc_auc": (
                roc_auc_score(test[target], probabilities)
                if test[target].nunique() == 2 else np.nan
            ),
        }
        results.append(row)

        for index, probability, prediction in zip(
            test.index, probabilities, predicted
        ):
            predictions.append({
                "attack_id": df.loc[index, "attack_id"],
                "source_attack_id": df.loc[index, "source_attack_id"],
                "held_out_category": category,
                "mode": df.loc[index, "mode"],
                "model": name,
                "actual": int(df.loc[index, target]),
                "predicted": int(prediction),
                "probability": float(probability),
            })

summary = pd.DataFrame(results)
summary.to_csv(OUTPUT / "heldout_category_metrics.csv", index=False)
pd.DataFrame(predictions).to_csv(
    OUTPUT / "heldout_category_predictions.csv", index=False
)

print("\nDATASET")
print("Records:", len(df))
print("Categories:", dict(Counter(df["category"])))

print("\nHELD-OUT CATEGORY RESULTS")
print(summary.to_string(index=False))

print("\nSaved results to:", OUTPUT)
