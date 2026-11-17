
from pathlib import Path
import pandas as pd
from sklearn.metrics import confusion_matrix

ROOT = Path(__file__).resolve().parents[1]

original = pd.read_csv(
    ROOT / "ml/data/v2_error_analysis.csv"
)

thresholds = [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60]

print("V2 ORIGINAL TICKETS — THRESHOLD ANALYSIS")
print(f"{'Threshold':<12}{'Accuracy':<12}{'Recall':<12}{'FPR':<12}{'FP':<8}{'FN':<8}")

for threshold in thresholds:
    predicted = (original["risk_score"] >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        original["actual"], predicted, labels=[0, 1]
    ).ravel()

    accuracy = (tp + tn) / (tp + tn + fp + fn)
    recall = tp / (tp + fn)
    fpr = fp / (fp + tn)

    print(
        f"{threshold:<12.2f}"
        f"{accuracy:<12.3f}"
        f"{recall:<12.3f}"
        f"{fpr:<12.3f}"
        f"{fp:<8}"
        f"{fn:<8}"
    )
