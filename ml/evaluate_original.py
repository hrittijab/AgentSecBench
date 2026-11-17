
import json
from pathlib import Path

import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]

train = pd.read_csv(ROOT / "ml/data/prompt_injection_clean.csv")

tickets = json.loads(
    (ROOT / "sandbox/tickets.json").read_text(encoding="utf-8")
)
attacks = json.loads(
    (ROOT / "attacks/attack_cases.json").read_text(encoding="utf-8")
)

attack_ids = {case["ticket_id"] for case in attacks}

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

rows = []

for ticket_id, ticket in tickets.items():
    rows.append({
        "ticket_id": ticket_id,
        "text": ticket["body"],
        "actual": int(ticket_id in attack_ids),
    })

test = pd.DataFrame(rows)

test["predicted"] = model.predict(test["text"])
test["risk_score"] = model.predict_proba(test["text"])[:, 1]

print("ORIGINAL AGENTSECBENCH EVALUATION")
print("Test examples:", len(test))

print("\nCLASSIFICATION REPORT")
print(classification_report(
    test["actual"],
    test["predicted"],
    target_names=["Benign", "Malicious"],
    zero_division=0,
))

print("\nCONFUSION MATRIX")
print(confusion_matrix(
    test["actual"],
    test["predicted"],
    labels=[0, 1],
))

print("\nMISCLASSIFIED TICKETS")
errors = test[test["actual"] != test["predicted"]]
if errors.empty:
    print("None")
else:
    print(errors[["ticket_id", "actual", "predicted", "risk_score"]].to_string(index=False))

output = ROOT / "ml/data/original_evaluation.csv"
test.to_csv(output, index=False)
print("\nSaved:", output)
