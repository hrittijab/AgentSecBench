import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"


def load_report(path):
    with Path(path).open(
        encoding="utf-8"
    ) as f:
        report = json.load(f)

    if not isinstance(report, dict):
        raise ValueError(
            "Expected report as a dictionary"
        )

    if "overall" not in report:
        raise ValueError(
            "Report is missing 'overall'"
        )

    if "categories" not in report:
        raise ValueError(
            "Report is missing 'categories'"
        )

    return report


def mode_order(modes):
    """
    Keep benchmark modes in a predictable order.
    """
    preferred = [
        "baseline",
        "defended",
    ]

    ordered = [
        mode
        for mode in preferred
        if mode in modes
    ]

    ordered.extend(
        sorted(
            mode
            for mode in modes
            if mode not in preferred
        )
    )

    return ordered


def save_attack_success_chart(
    report,
    output_path
):
    """
    Plot completed-trial attack success rate.

    Incomplete trials are deliberately excluded from
    the denominator because this chart represents
    verified completed-trial ASR.
    """
    overall = report["overall"]

    modes = mode_order(
        overall.keys()
    )

    rates = []

    for mode in modes:
        rate = overall[mode].get(
            "completed_attack_success_rate"
        )

        rates.append(
            0 if rate is None else rate * 100
        )

    fig, ax = plt.subplots(
        figsize=(7, 5)
    )

    bars = ax.bar(
        modes,
        rates
    )

    ax.set_ylabel(
        "Attack success rate (%)"
    )

    ax.set_title(
        "Completed-Trial Attack Success Rate"
    )

    ax.set_ylim(
        0,
        max(100, max(rates, default=0) + 10)
    )

    for bar, rate in zip(
        bars,
        rates
    ):
        ax.text(
            bar.get_x()
            + bar.get_width() / 2,
            bar.get_height() + 1,
            f"{rate:.1f}%",
            ha="center",
            va="bottom"
        )

    fig.tight_layout()

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    fig.savefig(
        output_path,
        dpi=200,
        bbox_inches="tight"
    )

    plt.close(fig)


def save_security_events_chart(
    report,
    output_path
):
    """
    Compare unauthorized security events across modes.
    """
    overall = report["overall"]

    modes = mode_order(
        overall.keys()
    )

    labels = [
        "Lookup\nattempts",
        "Lookup\nexecutions",
        "Email\nattempts",
        "Email\nexecutions",
        "Matched\ndisclosure",
    ]

    metric_names = [
        "unauthorized_lookup_attempts",
        "unauthorized_lookup_executions",
        "unauthorized_email_attempts",
        "unauthorized_email_executions",
    ]

    mode_values = {}

    for mode in modes:
        metrics = overall[mode]

        values = [
            metrics["security"][name]
            for name in metric_names
        ]

        values.append(
            metrics["disclosure"][
                "trials_with_matched_disclosure"
            ]
        )

        mode_values[mode] = values

    x = list(
        range(len(labels))
    )

    width = (
        0.8 / max(len(modes), 1)
    )

    fig, ax = plt.subplots(
        figsize=(10, 5)
    )

    for index, mode in enumerate(modes):
        offset = (
            index -
            (len(modes) - 1) / 2
        ) * width

        positions = [
            value + offset
            for value in x
        ]

        ax.bar(
            positions,
            mode_values[mode],
            width=width,
            label=mode
        )

    ax.set_xticks(x)
    ax.set_xticklabels(labels)

    ax.set_ylabel(
        "Event count"
    )

    ax.set_title(
        "Unauthorized Security Events"
    )

    ax.legend()

    fig.tight_layout()

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    fig.savefig(
        output_path,
        dpi=200,
        bbox_inches="tight"
    )

    plt.close(fig)


def save_category_asr_chart(
    report,
    output_path
):
    """
    Compare completed-trial ASR by attack category.
    """
    categories = report[
        "categories"
    ]

    category_names = sorted(
        categories.keys()
    )

    all_modes = set()

    for by_mode in categories.values():
        all_modes.update(
            by_mode.keys()
        )

    modes = mode_order(
        all_modes
    )

    x = list(
        range(len(category_names))
    )

    width = (
        0.8 / max(len(modes), 1)
    )

    fig_width = max(
        9,
        len(category_names) * 1.7
    )

    fig, ax = plt.subplots(
        figsize=(fig_width, 6)
    )

    for index, mode in enumerate(modes):
        rates = []

        for category in category_names:
            metrics = categories[
                category
            ].get(mode)

            if metrics is None:
                rates.append(0)
                continue

            rate = metrics.get(
                "completed_attack_success_rate"
            )

            rates.append(
                0
                if rate is None
                else rate * 100
            )

        offset = (
            index -
            (len(modes) - 1) / 2
        ) * width

        positions = [
            value + offset
            for value in x
        ]

        ax.bar(
            positions,
            rates,
            width=width,
            label=mode
        )

    labels = [
        category.replace(
            "_",
            " "
        ).title()
        for category in category_names
    ]

    ax.set_xticks(x)
    ax.set_xticklabels(
        labels,
        rotation=25,
        ha="right"
    )

    ax.set_ylabel(
        "Attack success rate (%)"
    )

    ax.set_title(
        "Completed-Trial ASR by Attack Category"
    )

    ax.set_ylim(
        0,
        100
    )

    ax.legend()

    fig.tight_layout()

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    fig.savefig(
        output_path,
        dpi=200,
        bbox_inches="tight"
    )

    plt.close(fig)


def generate_visualizations(
    report,
    source
):
    source = Path(
        source
    )

    output_dir = source.parent

    stem = source.stem

    if stem.endswith(
        "_report"
    ):
        stem = stem[
            :-len("_report")
        ]

    attack_success_path = (
        output_dir /
        f"{stem}_attack_success.png"
    )

    security_events_path = (
        output_dir /
        f"{stem}_security_events.png"
    )

    category_asr_path = (
        output_dir /
        f"{stem}_category_asr.png"
    )

    save_attack_success_chart(
        report,
        attack_success_path
    )

    save_security_events_chart(
        report,
        security_events_path
    )

    save_category_asr_chart(
        report,
        category_asr_path
    )

    return {
        "attack_success": (
            attack_success_path
        ),
        "security_events": (
            security_events_path
        ),
        "category_asr": (
            category_asr_path
        ),
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        required=True,
        help=(
            "Path to an AgentSecBench "
            "report JSON file"
        )
    )

    args = parser.parse_args()

    source = Path(
        args.input
    )

    report = load_report(
        source
    )

    outputs = generate_visualizations(
        report,
        source
    )

    print(
        "\nAGENTSECBENCH VISUALIZATIONS"
    )

    print("=" * 50)

    print(
        "Attack success:",
        outputs["attack_success"]
    )

    print(
        "Security events:",
        outputs["security_events"]
    )

    print(
        "Category ASR:",
        outputs["category_asr"]
    )


if __name__ == "__main__":
    main()