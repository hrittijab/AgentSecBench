
from pathlib import Path
from functools import lru_cache

import joblib

MODEL_PATH = (
    Path(__file__).resolve().parent
    / "models"
    / "prompt_injection_detector.joblib"
)


@lru_cache(maxsize=1)
def load_detector():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Detector model not found: {MODEL_PATH}"
        )

    return joblib.load(MODEL_PATH)


def detect_injection(text, threshold=0.5):
    """
    Score text for potential prompt injection.

    Returns a risk score and a classification.
    This function does not block or modify text.
    """

    if not isinstance(text, str):
        raise TypeError("Detector input must be a string")

    if not 0 <= threshold <= 1:
        raise ValueError("Threshold must be between 0 and 1")

    model = load_detector()

    risk_score = float(
        model.predict_proba([text])[0][1]
    )

    return {
        "risk_score": round(risk_score, 4),
        "is_suspicious": risk_score >= threshold,
        "threshold": threshold,
    }
