
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

from ml.detector import detect_injection

ROOT = Path(__file__).resolve().parents[1]

TICKETS_PATH = ROOT / "sandbox/tickets.json"
ATTACKS_PATH = ROOT / "attacks/attack_cases.json"
OUTPUT_PATH = ROOT / "ml/data/integrated_detector_results.csv"

# Load original AgentSecBench data
with open(TICKETS_PATH, encoding="utf-8") as f:
    tickets = json.load(f)

with open(ATTACKS_PATH, encoding="utf-8") as f:
    attacks = json.load(f)

# Identify malicious tickets using attack definitions
malicious_ticket_ids = {
    attack["ticket_id"]
    for attack in attacks
}

assert malicious_ticket_ids.issubset(set(tickets)), (
    "Some attack ticket IDs are missing from tickets.json"
)

rows = []

for ticket_id, ticket in tickets.items():

    body = ticket.get("body", "")

    if not isinstance(body, str):
        continue

    actual = int(ticket_id in malicious_ticket_ids)

    detection = detect_injection(
        body,
        threshold=0.5,
    )

    rows.append({
        "ticket_id": ticket_id,
        "subject": ticket.get("subject", ""),
        "body": body,
        "actual": actual,
        "predicted": int(detection["is_suspicious"]),
        "risk_score": detection["risk_score"],
    })

results = pd.DataFrame(rows)

y_true = results["actual"]
y_pred = results["predicted"]

print("\nINTEGRATED ML DETECTOR EVALUATION")
print("=" * 45)

print("Total tickets:", len(results))
print("Malicious:", int(y_true.sum()))
print("Benign:", int((y_true == 0).sum()))

print("\nMETRICS")
print("Accuracy:", round(
    accuracy_score(y_true, y_pred), 4
))
print("Precision:", round(
    precision_score(y_true, y_pred, zero_division=0), 4
))
print("Attack recall:", round(
    recall_score(y_true, y_pred, zero_division=0), 4
))
print("F1-score:", round(
    f1_score(y_true, y_pred, zero_division=0), 4
))

print("\nCLASSIFICATION REPORT")
print(classification_report(
    y_true,
    y_pred,
    labels=[0, 1],
    target_names=["Benign", "Malicious"],
    zero_division=0,
))

print("CONFUSION MATRIX")
print(confusion_matrix(
    y_true,
    y_pred,
    labels=[0, 1],
))

false_positives = results[
    (results["actual"] == 0)
    & (results["predicted"] == 1)
]

missed_attacks = results[
    (results["actual"] == 1)
    & (results["predicted"] == 0)
]

print("\nFALSE POSITIVES")
if false_positives.empty:
    print("None")
else:
    print(
        false_positives[
            ["ticket_id", "risk_score"]
        ].to_string(index=False)
    )

print("\nMISSED ATTACKS")
if missed_attacks.empty:
    print("None")
else:
    print(
        missed_attacks[
            ["ticket_id", "risk_score"]
        ].to_string(index=False)
    )

OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)

results.to_csv(OUTPUT_PATH, index=False)

print("\nSaved:", OUTPUT_PATH)
