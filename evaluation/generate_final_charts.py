
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
CHARTS = ROOT / "charts"
CHARTS.mkdir(exist_ok=True)

DEFENSES = [
    "baseline",
    "authorization",
    "prompt_guard",
    "layered",
    "ml_only",
    "ml_layered",
]

LABELS = [
    "Baseline",
    "Authorization",
    "Prompt guard",
    "Layered",
    "ML only",
    "ML + layered",
]


def wilson_interval(successes, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    p = successes / n
    denominator = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denominator
    margin = (
        z * np.sqrt(
            p * (1 - p) / n + z**2 / (4 * n**2)
        ) / denominator
    )
    return center - margin, center + margin


with open(RESULTS / "six_defense_comparison.json", encoding="utf-8") as f:
    attacks = json.load(f)

with open(RESULTS / "benign_six_defense_comparison.json", encoding="utf-8") as f:
    benign = json.load(f)


# Calculate attack outcomes directly from saved benchmark data.
attack_counts = {defense: 0 for defense in DEFENSES}
attack_totals = {defense: 0 for defense in DEFENSES}

for record in attacks:
    defense = record["defense"]

    if defense not in attack_counts:
        raise ValueError(f"Unexpected defense: {defense}")

    if record.get("metadata", {}).get("status") != "completed":
        raise ValueError(
            f"Incomplete attack trial: {record['attack_id']}"
        )

    attack_totals[defense] += 1

    if record["evaluation"]["attack_success"]:
        attack_counts[defense] += 1

assert len(attacks) == 180
assert all(attack_totals[d] == 30 for d in DEFENSES)

attack_n = 30


benign_summary = benign["summary"]
benign_counts = [
    benign_summary[d]["successful"] for d in DEFENSES
]
benign_n = [
    benign_summary[d]["trials"] for d in DEFENSES
]

assert sum(benign_n) == 300
assert all(n == 50 for n in benign_n)

attack_rates = np.array([
    100 * attack_counts[d] / attack_n for d in DEFENSES
])
benign_rates = np.array([
    100 * s / n for s, n in zip(benign_counts, benign_n)
])

def make_chart(values, successes, totals, title, ylabel, filename,
               color, ylim=(0, 100)):
    x = np.arange(len(DEFENSES))
    lower, upper = [], []

    for s, n in zip(successes, totals):
        lo, hi = wilson_interval(s, n)
        lower.append(100 * lo)
        upper.append(100 * hi)

    errors = np.array([
        values - np.array(lower),
        np.array(upper) - values,
    ])

    fig, ax = plt.subplots(figsize=(11, 6))
    ax.bar(x, values, color=color, alpha=0.85)
    ax.errorbar(
        x, values, yerr=errors, fmt="none",
        ecolor="black", capsize=5
    )
    ax.set_xticks(x, LABELS, rotation=15, ha="right")
    ax.set_ylim(*ylim)
    ax.set_ylabel(ylabel)
    ax.set_title(title, weight="bold")
    ax.grid(axis="y", alpha=0.2)

    for i, v in enumerate(values):
        ax.annotate(
            f"{v:.1f}%",
            (i, v),
            xytext=(0, -18 if v > 85 else 6),
            textcoords="offset points",
            ha="center",
            fontsize=10,
        )

    fig.tight_layout()
    fig.savefig(CHARTS / filename, dpi=200)
    plt.close(fig)


make_chart(
    attack_rates,
    [attack_counts[d] for d in DEFENSES],
    [attack_n] * 6,
    "Prompt-Injection Attack Success by Defense",
    "Attack success rate (%)",
    "attack_success_comparison.png",
    "#D95F5F",
    (0, 45),
)

make_chart(
    benign_rates,
    benign_counts,
    benign_n,
    "Legitimate Task Success by Defense",
    "Benign task success rate (%)",
    "benign_utility_comparison.png",
    "#3B82A0",
    (75, 105),
)

fig, ax = plt.subplots(figsize=(9, 6))
for i, label in enumerate(LABELS):
    ax.scatter(
        attack_rates[i], benign_rates[i],
        s=110, label=label
    )
    ax.annotate(
        label, (attack_rates[i], benign_rates[i]),
        xytext=(6, 6), textcoords="offset points",
        fontsize=9,
    )
ax.set_xlabel("Attack success rate (%) — lower is better")
ax.set_ylabel("Benign success rate (%) — higher is better")
ax.set_title("Security–Utility Tradeoff", weight="bold")
ax.set_xlim(-2, 28)
ax.set_ylim(93, 102)
ax.grid(alpha=0.25)
fig.tight_layout()
fig.savefig(CHARTS / "security_utility_tradeoff.png", dpi=200)
plt.close(fig)

print("Charts saved to:", CHARTS)
for path in CHARTS.glob("*.png"):
    print(" -", path.name)
