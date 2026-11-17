
import pandas as pd
from pathlib import Path
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parents[1]

df = pd.read_csv(ROOT / "ml/data/prompt_injection_clean.csv")

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

model.fit(df["text"], df["label"])

features = model.named_steps["tfidf"].get_feature_names_out()
weights = model.named_steps["classifier"].coef_[0]

ranked = pd.DataFrame({
    "feature": features,
    "weight": weights,
})

print("\nTOP 20 MALICIOUS INDICATORS")
print(
    ranked.sort_values("weight", ascending=False)
    .head(20)
    .to_string(index=False)
)

print("\nTOP 20 BENIGN INDICATORS")
print(
    ranked.sort_values("weight")
    .head(20)
    .to_string(index=False)
)
