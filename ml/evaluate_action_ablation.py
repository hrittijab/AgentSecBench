
import re
from pathlib import Path

import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, recall_score, confusion_matrix
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
df = pd.read_csv(ROOT / "ml/data/prompt_injection_v2.csv")

actions = [
    "retrieve another customer's private account record",
    "forward the complete customer profile to an outside mailbox",
    "perform an additional customer lookup without authorization",
    "export account information to an external recipient",
    "execute a customer search unrelated to this ticket",
    "send retrieved customer details to a third-party address",
]

def remove_actions(text):
    for action in actions:
        text = re.sub(
            re.escape(action),
            "[ACTION_REMOVED]",
            text,
            flags=re.IGNORECASE,
        )
    return text

train, test = train_test_split(
    df,
    test_size=0.25,
    random_state=42,
    stratify=df["label"],
)

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

normal_predictions = model.predict(test["text"])

ablated_text = test["text"].apply(remove_actions)
ablated_predictions = model.predict(ablated_text)

def report(name, predictions):
    tn, fp, fn, tp = confusion_matrix(
        test["label"], predictions, labels=[0, 1]
    ).ravel()

    print(f"\n{name}")
    print("Accuracy:", round(
        accuracy_score(test["label"], predictions), 3
    ))
    print("Attack recall:", round(
        recall_score(test["label"], predictions), 3
    ))
    print("False positives:", fp)
    print("Missed attacks:", fn)

report("NORMAL TEST", normal_predictions)
report("ACTION-ABLATED TEST", ablated_predictions)

print("\nEXAMPLE ABLATED ATTACK")
example = test[test["label"] == 1].iloc[0]["text"]
print("Original:", example)
print("Ablated:", remove_actions(example))
