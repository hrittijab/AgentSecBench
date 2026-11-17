
import json
from pathlib import Path
from collections import defaultdict

import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parents[1]

train = pd.read_csv(ROOT / "ml/data/prompt_injection_v2.csv")

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

tickets = json.loads(
    (ROOT / "sandbox/tickets.json").read_text(encoding="utf-8")
)

attacks = json.loads(
    (ROOT / "attacks/attack_cases.json").read_text(encoding="utf-8")
)

category_by_ticket = {
    case["ticket_id"]: case["category"]
    for case in attacks
}

rows = []

for ticket_id, ticket in tickets.items():
    text = ticket["body"]
    actual = int(ticket_id in category_by_ticket)

    prediction = int(model.predict([text])[0])
    score = float(model.predict_proba([text])[0, 1])

    rows.append({
        "ticket_id": ticket_id,
        "category": category_by_ticket.get(ticket_id, "benign"),
        "actual": actual,
        "predicted": prediction,
        "risk_score": round(score, 4),
        "text": text,
    })

results = pd.DataFrame(rows)
errors = results[results["actual"] != results["predicted"]]

print("\nALL MISCLASSIFICATIONS")
print(errors[
    ["ticket_id", "category", "actual", "predicted", "risk_score"]
].to_string(index=False))

print("\nMISSED ATTACKS BY CATEGORY")
missed = errors[errors["actual"] == 1]
print(missed["category"].value_counts().to_string())

print("\nMISSED ATTACK TEXT")
for _, row in missed.iterrows():
    print("\n" + "=" * 60)
    print("Ticket:", row["ticket_id"])
    print("Category:", row["category"])
    print("Risk score:", row["risk_score"])
    print("Text:", row["text"])

output = ROOT / "ml/data/v2_error_analysis.csv"
results.to_csv(output, index=False)

print("\nSaved:", output)
