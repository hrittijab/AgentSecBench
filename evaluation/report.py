import argparse
import csv
import json

from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from evaluation.security_metrics import analyze_trial
from evaluation.exfiltration import detect_exfiltration


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"
ATTACKS_PATH = ROOT / "attacks" / "generated_attacks.json"
CUSTOMERS_PATH = ROOT / "sandbox" / "customers.json"


SECURITY_FIELDS = (
    "unauthorized_lookup_attempts",
    "unauthorized_lookup_executions",
    "unauthorized_email_attempts",
    "unauthorized_email_executions",
    "blocked_lookup_calls",
    "blocked_email_calls",
)


# ============================================================
# Loading
# ============================================================


def load_json(path):
    with Path(path).open(
        encoding="utf-8"
    ) as f:
        return json.load(f)


def build_permissions(attacks):
    return {
        attack["attack_id"]: {
            "allowed_customer_ids": attack[
                "allowed_customer_ids"
            ],
            "allowed_recipients": attack[
                "allowed_recipients"
            ],
        }
        for attack in attacks
    }


# ============================================================
# Validation
# ============================================================


def validate_trials(trials, permissions):
    """
    Validate report inputs.

    Never silently analyze a trial using missing or
    incorrect permissions.
    """

    seen = set()

    for trial in trials:
        attack_id = trial["attack_id"]
        mode = trial["mode"]

        key = (
            attack_id,
            mode,
        )

        if key in seen:
            raise ValueError(
                f"Duplicate trial: {key}"
            )

        seen.add(key)

        if attack_id not in permissions:
            raise ValueError(
                "Missing permissions for "
                f"attack {attack_id}. "
                "Check that the attack dataset "
                "matches the benchmark results."
            )


# ============================================================
# Security summary
# ============================================================


def summarize(
    trials,
    permissions,
    customers,
):
    total = len(trials)

    statuses = Counter(
        trial.get(
            "status",
            "unknown",
        )
        for trial in trials
    )

    completed = [
        trial
        for trial in trials
        if trial.get("valid_trial") is True
    ]

    legacy = [
        trial
        for trial in trials
        if "valid_trial" not in trial
    ]

    security = Counter({
        field: 0
        for field in SECURITY_FIELDS
    })

    disclosure_trials = 0
    disclosure_findings = 0

    disclosed_customers = Counter()
    disclosure_recipients = Counter()

    for trial in trials:
        attack_id = trial["attack_id"]
        allowed = permissions[attack_id]

        metrics = analyze_trial(
            trial,
            allowed["allowed_customer_ids"],
            allowed["allowed_recipients"],
        )

        security.update(metrics)

        disclosure = detect_exfiltration(
            trial,
            customers,
            allowed["allowed_recipients"],
        )

        if disclosure[
            "confirmed_exfiltration"
        ]:
            disclosure_trials += 1

        for finding in disclosure["findings"]:
            disclosure_findings += 1

            disclosed_customers[
                finding["customer_id"]
            ] += 1

            disclosure_recipients[
                finding["recipient"]
            ] += 1

    observed_successes = sum(
        bool(
            trial.get("attack_success")
        )
        for trial in trials
    )

    completed_successes = sum(
        bool(
            trial.get("attack_success")
        )
        for trial in completed
    )

    return {
        "trials": total,

        "statuses": dict(statuses),

        "completed": len(completed),

        "legacy_unverified": len(legacy),

        "observed_attack_successes": (
            observed_successes
        ),

        "observed_attack_success_rate": (
            round(
                observed_successes / total,
                4,
            )
            if total
            else None
        ),

        "completed_attack_successes": (
            completed_successes
        ),

        "completed_attack_success_rate": (
            round(
                completed_successes
                / len(completed),
                4,
            )
            if completed
            else None
        ),

        "errors": sum(
            trial.get("error") is not None
            for trial in trials
        ),

        "truncated": statuses.get(
            "truncated",
            0,
        ),

        "timeouts": statuses.get(
            "timeout",
            0,
        ),

        "security": {
            field: security[field]
            for field in SECURITY_FIELDS
        },

        "disclosure": {
            "trials_with_matched_disclosure": (
                disclosure_trials
            ),

            "matched_customer_recipient_pairs": (
                disclosure_findings
            ),

            "customer_counts": dict(
                disclosed_customers
            ),

            "recipient_counts": dict(
                disclosure_recipients
            ),
        },
    }


# ============================================================
# Defense comparison
# ============================================================


def build_defense_comparison(overall):
    """
    Compare every non-baseline strategy against baseline.

    Attack-success reductions are expressed as absolute
    percentage-point differences rather than relative security
    improvements.

    Observed and completion-aware metrics remain separate so
    incomplete trials are not silently treated as secure
    outcomes.
    """

    baseline = overall.get("baseline")

    if baseline is None:
        return {}

    baseline_observed = baseline.get(
        "observed_attack_success_rate"
    )

    baseline_completed = baseline.get(
        "completed_attack_success_rate"
    )

    comparison = {}

    for mode, metrics in overall.items():
        if mode == "baseline":
            continue

        observed_rate = metrics.get(
            "observed_attack_success_rate"
        )

        completed_rate = metrics.get(
            "completed_attack_success_rate"
        )

        observed_reduction = None

        if (
            baseline_observed is not None
            and observed_rate is not None
        ):
            observed_reduction = round(
                baseline_observed
                - observed_rate,
                4,
            )

        completed_reduction = None

        if (
            baseline_completed is not None
            and completed_rate is not None
        ):
            completed_reduction = round(
                baseline_completed
                - completed_rate,
                4,
            )

        comparison[mode] = {
            "observed_attack_success_rate": (
                observed_rate
            ),

            "completed_attack_success_rate": (
                completed_rate
            ),

            "observed_attack_success_reduction": (
                observed_reduction
            ),

            "completed_attack_success_reduction": (
                completed_reduction
            ),

            "unauthorized_lookup_attempts": (
                metrics["security"][
                    "unauthorized_lookup_attempts"
                ]
            ),

            "unauthorized_lookup_executions": (
                metrics["security"][
                    "unauthorized_lookup_executions"
                ]
            ),

            "unauthorized_email_attempts": (
                metrics["security"][
                    "unauthorized_email_attempts"
                ]
            ),

            "unauthorized_email_executions": (
                metrics["security"][
                    "unauthorized_email_executions"
                ]
            ),

            "blocked_lookup_calls": (
                metrics["security"][
                    "blocked_lookup_calls"
                ]
            ),

            "blocked_email_calls": (
                metrics["security"][
                    "blocked_email_calls"
                ]
            ),

            "disclosure_trials": (
                metrics["disclosure"][
                    "trials_with_matched_disclosure"
                ]
            ),

            "matched_customer_recipient_pairs": (
                metrics["disclosure"][
                    "matched_customer_recipient_pairs"
                ]
            ),
        }

    return comparison


# ============================================================
# Report generation
# ============================================================


def generate_report(
    trials,
    source,
    permissions,
    customers,
):
    validate_trials(
        trials,
        permissions,
    )

    modes = defaultdict(list)

    categories = defaultdict(
        lambda: defaultdict(list)
    )

    for trial in trials:
        mode = trial["mode"]

        category = trial.get(
            "category",
            "unknown",
        )

        modes[mode].append(trial)

        categories[
            category
        ][mode].append(trial)

    overall = {
        mode: summarize(
            items,
            permissions,
            customers,
        )
        for mode, items in modes.items()
    }

    category_report = {
        category: {
            mode: summarize(
                items,
                permissions,
                customers,
            )
            for mode, items
            in by_mode.items()
        }
        for category, by_mode
        in categories.items()
    }

    return {
        "generated_at": (
            datetime.now().isoformat()
        ),

        "source": str(source),

        "methodology": {
            "observed_attack_success": (
                "Original attack-specific "
                "tool-execution objective, "
                "measured across all trials."
            ),

            "completed_attack_success": (
                "Attack-specific success "
                "among verified completed "
                "trials only."
            ),

            "legacy_results": (
                "Trials without completion "
                "metadata are not assumed "
                "to have completed."
            ),

            "security_events": (
                "Permission-aware counts "
                "of attempted, executed, "
                "and blocked tool actions. "
                "These counts include "
                "incomplete trials."
            ),

            "disclosure_detection": (
                "Value matching against "
                "synthetic customer fields "
                "in executed emails to "
                "unauthorized recipients. "
                "Supports plaintext and "
                "selected Base64 encodings. "
                "This is not proof that "
                "all possible disclosures "
                "were detected."
            ),

            "defense_comparison": (
                "Each non-baseline strategy "
                "is compared with baseline "
                "using absolute attack-success-rate "
                "differences. Reductions are "
                "percentage-point reductions, "
                "not claims of percentage security "
                "improvement."
            ),
        },

        "overall": overall,

        "defense_comparison": (
            build_defense_comparison(
                overall
            )
        ),

        "categories": category_report,
    }


# ============================================================
# CSV exports
# ============================================================


def export_overall_csv(
    report,
    path,
):
    """
    Export one row per benchmark mode.

    Rates are stored as decimal fractions so downstream tools
    can format them as percentages without parsing
    presentation strings.
    """

    path = Path(path)

    fieldnames = [
        "mode",
        "trials",
        "completed",
        "legacy_unverified",
        "observed_attack_successes",
        "observed_attack_success_rate",
        "completed_attack_successes",
        "completed_attack_success_rate",
        "errors",
        "truncated",
        "timeouts",
        *SECURITY_FIELDS,
        "trials_with_matched_disclosure",
        "matched_customer_recipient_pairs",
    ]

    rows = []

    for mode, metrics in (
        report["overall"].items()
    ):
        row = {
            "mode": mode,

            "trials": metrics[
                "trials"
            ],

            "completed": metrics[
                "completed"
            ],

            "legacy_unverified": metrics[
                "legacy_unverified"
            ],

            "observed_attack_successes": metrics[
                "observed_attack_successes"
            ],

            "observed_attack_success_rate": metrics[
                "observed_attack_success_rate"
            ],

            "completed_attack_successes": metrics[
                "completed_attack_successes"
            ],

            "completed_attack_success_rate": metrics[
                "completed_attack_success_rate"
            ],

            "errors": metrics[
                "errors"
            ],

            "truncated": metrics[
                "truncated"
            ],

            "timeouts": metrics[
                "timeouts"
            ],

            "trials_with_matched_disclosure": (
                metrics["disclosure"][
                    "trials_with_matched_disclosure"
                ]
            ),

            "matched_customer_recipient_pairs": (
                metrics["disclosure"][
                    "matched_customer_recipient_pairs"
                ]
            ),
        }

        for field in SECURITY_FIELDS:
            row[field] = (
                metrics["security"][field]
            )

        rows.append(row)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


def export_categories_csv(
    report,
    path,
):
    """
    Export category-level benchmark metrics.
    """

    path = Path(path)

    fieldnames = [
        "category",
        "mode",
        "trials",
        "completed",
        "observed_attack_successes",
        "observed_attack_success_rate",
        "completed_attack_successes",
        "completed_attack_success_rate",
        "truncated",
        "timeouts",
        *SECURITY_FIELDS,
        "trials_with_matched_disclosure",
        "matched_customer_recipient_pairs",
    ]

    rows = []

    for category, modes in (
        report["categories"].items()
    ):
        for mode, metrics in (
            modes.items()
        ):
            row = {
                "category": category,

                "mode": mode,

                "trials": metrics[
                    "trials"
                ],

                "completed": metrics[
                    "completed"
                ],

                "observed_attack_successes": metrics[
                    "observed_attack_successes"
                ],

                "observed_attack_success_rate": metrics[
                    "observed_attack_success_rate"
                ],

                "completed_attack_successes": metrics[
                    "completed_attack_successes"
                ],

                "completed_attack_success_rate": metrics[
                    "completed_attack_success_rate"
                ],

                "truncated": metrics[
                    "truncated"
                ],

                "timeouts": metrics[
                    "timeouts"
                ],

                "trials_with_matched_disclosure": (
                    metrics["disclosure"][
                        "trials_with_matched_disclosure"
                    ]
                ),

                "matched_customer_recipient_pairs": (
                    metrics["disclosure"][
                        "matched_customer_recipient_pairs"
                    ]
                ),
            }

            for field in SECURITY_FIELDS:
                row[field] = (
                    metrics["security"][field]
                )

            rows.append(row)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


def export_defense_comparison_csv(
    report,
    path,
):
    """
    Export one row per non-baseline defense strategy.
    """

    path = Path(path)

    fieldnames = [
        "mode",
        "observed_attack_success_rate",
        "completed_attack_success_rate",
        "observed_attack_success_reduction",
        "completed_attack_success_reduction",
        "unauthorized_lookup_attempts",
        "unauthorized_lookup_executions",
        "unauthorized_email_attempts",
        "unauthorized_email_executions",
        "blocked_lookup_calls",
        "blocked_email_calls",
        "disclosure_trials",
        "matched_customer_recipient_pairs",
    ]

    rows = []

    for mode, metrics in (
        report.get(
            "defense_comparison",
            {},
        ).items()
    ):
        rows.append({
            "mode": mode,
            **metrics,
        })

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


# ============================================================
# Console output
# ============================================================


def print_report(report):
    print(
        "\nAGENTSECBENCH SECURITY REPORT"
    )

    print("=" * 60)

    for mode, metrics in (
        report["overall"].items()
    ):
        print(
            f"\n{mode.upper()}"
        )

        print("-" * 40)

        print(
            "Trials:",
            metrics["trials"],
        )

        print(
            "Completed:",
            metrics["completed"],
        )

        print(
            "Legacy unverified:",
            metrics["legacy_unverified"],
        )

        print(
            "Statuses:",
            metrics["statuses"],
        )

        print(
            "Observed attack successes:",
            metrics[
                "observed_attack_successes"
            ],
        )

        observed_rate = metrics[
            "observed_attack_success_rate"
        ]

        if observed_rate is not None:
            print(
                "Observed attack success rate:",
                f"{observed_rate * 100:.1f}%",
            )

        print(
            "Completed attack successes:",
            metrics[
                "completed_attack_successes"
            ],
        )

        completed_rate = metrics[
            "completed_attack_success_rate"
        ]

        if completed_rate is not None:
            print(
                "Completed attack success rate:",
                f"{completed_rate * 100:.1f}%",
            )

        print(
            "\nAuthorization security:"
        )

        for field, count in (
            metrics["security"].items()
        ):
            print(
                f"  {field}: {count}"
            )

        print(
            "\nSynthetic-data disclosure:"
        )

        disclosure = metrics[
            "disclosure"
        ]

        print(
            "  Trials with matched disclosure:",
            disclosure[
                "trials_with_matched_disclosure"
            ],
        )

        print(
            "  Matched customer-recipient pairs:",
            disclosure[
                "matched_customer_recipient_pairs"
            ],
        )

    print(
        "\nCATEGORY BREAKDOWN"
    )

    print("-" * 60)

    for category, modes in (
        report["categories"].items()
    ):
        print(
            f"\n{category}"
        )

        for mode, metrics in (
            modes.items()
        ):
            observed_rate = metrics[
                "observed_attack_success_rate"
            ]

            completed_rate = metrics[
                "completed_attack_success_rate"
            ]

            observed_display = (
                f"{observed_rate * 100:.1f}%"
                if observed_rate is not None
                else "N/A"
            )

            completed_display = (
                f"{completed_rate * 100:.1f}%"
                if completed_rate is not None
                else "N/A"
            )

            print(
                f"  {mode}: "
                f"{metrics['observed_attack_successes']}"
                f"/{metrics['trials']} "
                f"observed successes "
                f"({observed_display}); "
                f"{metrics['completed_attack_successes']}"
                f"/{metrics['completed']} "
                f"completed successes "
                f"({completed_display}); "
                f"{metrics['disclosure']['trials_with_matched_disclosure']} "
                "disclosure trials"
            )

    comparison = report.get(
        "defense_comparison",
        {},
    )

    if comparison:
        print(
            "\nDEFENSE COMPARISON VS BASELINE"
        )

        print("-" * 60)

        for mode, metrics in (
            comparison.items()
        ):
            print(
                f"\n{mode.upper()}"
            )

            observed = metrics[
                "observed_attack_success_reduction"
            ]

            completed = metrics[
                "completed_attack_success_reduction"
            ]

            observed_display = (
                f"{observed * 100:.1f} "
                "percentage points"
                if observed is not None
                else "N/A"
            )

            completed_display = (
                f"{completed * 100:.1f} "
                "percentage points"
                if completed is not None
                else "N/A"
            )

            print(
                "  Observed ASR reduction:",
                observed_display,
            )

            print(
                "  Completed ASR reduction:",
                completed_display,
            )

            print(
                "  Unauthorized lookup attempts:",
                metrics[
                    "unauthorized_lookup_attempts"
                ],
            )

            print(
                "  Unauthorized lookup executions:",
                metrics[
                    "unauthorized_lookup_executions"
                ],
            )

            print(
                "  Unauthorized email attempts:",
                metrics[
                    "unauthorized_email_attempts"
                ],
            )

            print(
                "  Unauthorized email executions:",
                metrics[
                    "unauthorized_email_executions"
                ],
            )

            print(
                "  Blocked lookup calls:",
                metrics[
                    "blocked_lookup_calls"
                ],
            )

            print(
                "  Blocked email calls:",
                metrics[
                    "blocked_email_calls"
                ],
            )

            print(
                "  Disclosure trials:",
                metrics[
                    "disclosure_trials"
                ],
            )


# ============================================================
# CLI
# ============================================================


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        required=True,
    )

    parser.add_argument(
        "--output",
        default=None,
    )

    parser.add_argument(
        "--attacks",
        default=str(
            ATTACKS_PATH
        ),
    )

    parser.add_argument(
        "--customers",
        default=str(
            CUSTOMERS_PATH
        ),
    )

    args = parser.parse_args()

    source = Path(
        args.input
    )

    trials = load_json(
        source
    )

    attacks = load_json(
        args.attacks
    )

    customers = load_json(
        args.customers
    )

    if not isinstance(
        trials,
        list,
    ):
        raise ValueError(
            "Expected trial results as a list"
        )

    if not isinstance(
        attacks,
        list,
    ):
        raise ValueError(
            "Expected attack dataset as a list"
        )

    if not isinstance(
        customers,
        dict,
    ):
        raise ValueError(
            "Expected customers as a dictionary"
        )

    permissions = build_permissions(
        attacks
    )

    report = generate_report(
        trials,
        source,
        permissions,
        customers,
    )

    output = (
        Path(args.output)
        if args.output
        else RESULTS_DIR / (
            source.stem
            + "_report.json"
        )
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            report,
            f,
            indent=2,
        )

    # --------------------------------------------------------
    # Export machine-readable tables
    # --------------------------------------------------------

    overall_csv = output.with_name(
        source.stem
        + "_summary.csv"
    )

    categories_csv = output.with_name(
        source.stem
        + "_categories.csv"
    )

    comparison_csv = output.with_name(
        source.stem
        + "_defense_comparison.csv"
    )

    export_overall_csv(
        report,
        overall_csv,
    )

    export_categories_csv(
        report,
        categories_csv,
    )

    export_defense_comparison_csv(
        report,
        comparison_csv,
    )

    # --------------------------------------------------------
    # Console report
    # --------------------------------------------------------

    print_report(
        report
    )

    print(
        "\nSaved report artifacts:"
    )

    print(
        "  JSON:",
        output,
    )

    print(
        "  Summary CSV:",
        overall_csv,
    )

    print(
        "  Categories CSV:",
        categories_csv,
    )

    print(
        "  Defense comparison CSV:",
        comparison_csv,
    )


if __name__ == "__main__":
    main()