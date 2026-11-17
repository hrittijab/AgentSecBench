
from pathlib import Path

import joblib
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parents[1]

DATA_PATH = ROOT / "ml/data/prompt_injection_v2.csv"
MODEL_PATH = ROOT / "ml/models/prompt_injection_detector.joblib"

df = pd.read_csv(DATA_PATH)

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
        ),
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        ),
    ),
])

model.fit(df["text"], df["label"])

MODEL_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)

joblib.dump(model, MODEL_PATH)

print("Training examples:", len(df))
print("Model saved:", MODEL_PATH)
