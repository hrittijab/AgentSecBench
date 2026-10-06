import argparse
import json

from datetime import datetime
from pathlib import Path

from agent.agent import run_agent
from agent.defenses import DEFENSES, get_defense
from agent.tools import audit_log, reset_audit_log
from agent.policy import policy_log, reset_policy_log
from evaluation.benign_evaluator import evaluate_benign_case


BASE_DIR = Path(__file__).resolve().parent.parent

DEFAULT_DEFENSES = (
    "baseline",
    "prompt_guard",
    "authorization",
    "layered",
)


# ============================================================
# Loading
# ============================================================


def load_benign_cases():
    path = (
        BASE_DIR
        / "attacks"
        / "benign_cases.json"
    )

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


# ============================================================
# Defense normalization
# ============================================================


def normalize_defense(
    defense=None,
    enforce_policy=None,
):
    """
    Resolve the defense strategy.

    New interface:
        defense="baseline"
        defense="prompt_guard"
        defense="authorization"
        defense="layered"

    Legacy interface:
        enforce_policy=False -> baseline
        enforce_policy=True  -> authorization

    If neither argument is supplied, preserve the historical
    benign-runner default of authorization.
    """

    if defense is not None:
        if enforce_policy is not None:
            raise ValueError(
                "Specify either 'defense' or legacy "
                "'enforce_policy', not both."
            )

        return get_defense(defense).name

    if enforce_policy is not None:
        return (
            "authorization"
            if enforce_policy
            else "baseline"
        )

    return "authorization"


# ============================================================
# Single benign trial
# ============================================================


def run_benign_case(
    case,
    defense=None,
    enforce_policy=None,
):
    """
    Run one benign benchmark case against one defense.

    The returned record contains the defense name, tool audit
    information, policy decisions, and benign-task evaluation.
    """

    defense_name = normalize_defense(
        defense=defense,
        enforce_policy=enforce_policy,
    )

    reset_audit_log()
    reset_policy_log()

    agent_response = run_agent(
        case["user_request"],
        allowed_customer_ids=(
            case["allowed_customer_ids"]
        ),
        allowed_recipients=(
            case["allowed_recipients"]
        ),
        defense=defense_name,
    )

    evaluation = evaluate_benign_case(
        audit_log=audit_log,
        expected_tool=case["expected_tool"],
        expected_arguments=case[
            "expected_arguments"
        ],
    )

    return {
        "case_id": case["case_id"],
        "name": case["name"],
        "mode": defense_name,
        "defense": defense_name,
        "agent_response": agent_response,
        "audit_log": audit_log.copy(),
        "policy_log": policy_log.copy(),
        "evaluation": evaluation,
    }


# ============================================================
# Single-defense benchmark
# ============================================================


def run_all_benign_cases(
    defense=None,
    enforce_policy=None,
):
    """
    Run every benign case against one defense.

    This preserves the historical API.

    If no arguments are supplied, authorization is used,
    matching the original benign runner behavior.
    """

    defense_name = normalize_defense(
        defense=defense,
        enforce_policy=enforce_policy,
    )

    cases = load_benign_cases()
    results = []

    for case in cases:
        print(
            "\n[Benign Benchmark] Running "
            f"{case['case_id']} "
            f"[{defense_name}]"
        )

        result = run_benign_case(
            case,
            defense=defense_name,
        )

        results.append(result)

    return results


# ============================================================
# Multi-defense benchmark
# ============================================================


def run_benign_defense_comparison(
    defenses=None,
):
    """
    Run every benign case against multiple defense strategies.

    Returns one flat result list containing one record per
    case/defense pair.
    """

    if defenses is None:
        defenses = DEFAULT_DEFENSES

    defense_names = []

    for defense in defenses:
        defense_name = get_defense(
            defense
        ).name

        if defense_name not in defense_names:
            defense_names.append(
                defense_name
            )

    cases = load_benign_cases()
    results = []

    for case in cases:
        for defense_name in defense_names:
            print(
                "\n[Benign Benchmark] Running "
                f"{case['case_id']} "
                f"[{defense_name}]"
            )

            result = run_benign_case(
                case,
                defense=defense_name,
            )

            results.append(result)

    return results


# ============================================================
# Utility metrics
# ============================================================


def summarize_benign_results(results):
    """
    Produce benign utility metrics for each defense.

    A benign trial succeeds when benign_evaluator reports
    benign_success=True.

    Correctness is therefore based on expected tool execution,
    rather than on the model's natural-language response.
    """

    summaries = {}

    for result in results:
        defense_name = result.get(
            "defense",
            result.get(
                "mode",
                "unknown",
            ),
        )

        if defense_name not in summaries:
            summaries[defense_name] = {
                "trials": 0,
                "successful": 0,
                "failed": 0,
                "utility_rate": None,
            }

        summary = summaries[
            defense_name
        ]

        summary["trials"] += 1

        evaluation = result.get(
            "evaluation",
            {},
        )

        success = bool(
            evaluation.get(
                "benign_success"
            )
        )

        if success:
            summary["successful"] += 1

        else:
            summary["failed"] += 1

    for summary in summaries.values():
        trials = summary[
            "trials"
        ]

        summary["utility_rate"] = (
            round(
                summary["successful"]
                / trials,
                4,
            )
            if trials
            else None
        )

    return summaries


def calculate_utility_change(
    summaries,
):
    """
    Compare benign utility against baseline.

    Positive values indicate higher observed benign utility
    than baseline.

    Negative values indicate lower observed benign utility.

    These are absolute percentage-point differences, not
    relative percentage changes.
    """

    baseline = summaries.get(
        "baseline"
    )

    if baseline is None:
        return {}

    baseline_rate = baseline.get(
        "utility_rate"
    )

    comparison = {}

    for defense_name, summary in (
        summaries.items()
    ):
        if defense_name == "baseline":
            continue

        utility_rate = summary.get(
            "utility_rate"
        )

        change = None

        if (
            baseline_rate is not None
            and utility_rate is not None
        ):
            change = round(
                utility_rate
                - baseline_rate,
                4,
            )

        comparison[
            defense_name
        ] = {
            "utility_rate": utility_rate,

            "utility_change_vs_baseline": (
                change
            ),

            "successful": summary[
                "successful"
            ],

            "failed": summary[
                "failed"
            ],

            "trials": summary[
                "trials"
            ],
        }

    return comparison


# ============================================================
# Console reporting
# ============================================================


def print_benign_report(
    summaries,
    comparison,
):
    print(
        "\nAGENTSECBENCH BENIGN UTILITY REPORT"
    )

    print("=" * 60)

    for defense_name, summary in (
        summaries.items()
    ):
        utility_rate = summary[
            "utility_rate"
        ]

        utility_display = (
            f"{utility_rate * 100:.1f}%"
            if utility_rate is not None
            else "N/A"
        )

        print(
            f"\n{defense_name.upper()}"
        )

        print("-" * 40)

        print(
            "Trials:",
            summary["trials"],
        )

        print(
            "Successful:",
            summary["successful"],
        )

        print(
            "Failed:",
            summary["failed"],
        )

        print(
            "Benign utility rate:",
            utility_display,
        )

    if not comparison:
        return

    print(
        "\nUTILITY CHANGE VS BASELINE"
    )

    print("-" * 60)

    for defense_name, metrics in (
        comparison.items()
    ):
        change = metrics[
            "utility_change_vs_baseline"
        ]

        if change is None:
            display = "N/A"

        elif change > 0:
            display = (
                f"+{change * 100:.1f} "
                "percentage points"
            )

        else:
            display = (
                f"{change * 100:.1f} "
                "percentage points"
            )

        print(
            f"{defense_name}: {display}"
        )


# ============================================================
# Artifact generation
# ============================================================


def build_benign_artifact(
    results,
    defenses,
):
    """
    Build the machine-readable benign benchmark artifact.
    """

    summaries = summarize_benign_results(
        results
    )

    comparison = calculate_utility_change(
        summaries
    )

    return {
        "benchmark": "benign_utility",

        "generated_at": (
            datetime.now().isoformat()
        ),

        "defenses": list(
            defenses
        ),

        "methodology": {
            "benign_success": (
                "A benign case succeeds when the expected "
                "tool is executed with the expected arguments."
            ),

            "utility_rate": (
                "Fraction of benign benchmark trials that "
                "successfully execute the expected legitimate "
                "tool action."
            ),

            "utility_change_vs_baseline": (
                "Absolute benign utility-rate difference "
                "relative to baseline, expressed as a decimal "
                "fraction. This represents a percentage-point "
                "difference when displayed as a percentage."
            ),
        },

        "results": results,

        "summary": summaries,

        "comparison_vs_baseline": (
            comparison
        ),
    }


# ============================================================
# CLI
# ============================================================


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Run the AgentSecBench benign utility benchmark "
            "across defense strategies."
        )
    )

    parser.add_argument(
        "--defenses",
        nargs="+",
        choices=sorted(DEFENSES),
        default=list(DEFAULT_DEFENSES),
        help=(
            "Defense strategies to evaluate. "
            "Defaults to baseline, prompt_guard, "
            "authorization, and layered."
        ),
    )

    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Optional output JSON path. "
            "If omitted, results are written "
            "to the results directory."
        ),
    )

    args = parser.parse_args()

    results = (
        run_benign_defense_comparison(
            defenses=args.defenses,
        )
    )

    artifact = build_benign_artifact(
        results,
        args.defenses,
    )

    if args.output:
        output = Path(
            args.output
        )

    else:
        timestamp = (
            datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )
        )

        output = (
            BASE_DIR
            / "results"
            / (
                "benign_utility_"
                f"{timestamp}.json"
            )
        )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            artifact,
            file,
            indent=2,
        )

    print_benign_report(
        artifact["summary"],
        artifact[
            "comparison_vs_baseline"
        ],
    )

    print(
        "\nSaved:",
        output,
    )


if __name__ == "__main__":
    main()