import json

import matplotlib
import pytest

matplotlib.use("Agg")

from evaluation.visualize import (
    display_mode,
    generate_visualizations,
    load_report,
    mode_order,
    save_attack_success_chart,
    save_category_asr_chart,
    save_security_events_chart,
)


# ============================================================
# Synthetic report
# ============================================================


def make_mode_metrics(
    completed_asr,
    lookup_attempts=0,
    lookup_executions=0,
    email_attempts=0,
    email_executions=0,
    disclosures=0,
):
    return {
        "completed_attack_success_rate": completed_asr,
        "security": {
            "unauthorized_lookup_attempts": (
                lookup_attempts
            ),
            "unauthorized_lookup_executions": (
                lookup_executions
            ),
            "unauthorized_email_attempts": (
                email_attempts
            ),
            "unauthorized_email_executions": (
                email_executions
            ),
        },
        "disclosure": {
            "trials_with_matched_disclosure": (
                disclosures
            ),
        },
    }


def make_report():
    return {
        "overall": {
            "baseline": make_mode_metrics(
                completed_asr=0.60,
                lookup_attempts=10,
                lookup_executions=10,
                email_attempts=8,
                email_executions=8,
                disclosures=6,
            ),
            "prompt_guard": make_mode_metrics(
                completed_asr=0.30,
                lookup_attempts=5,
                lookup_executions=5,
                email_attempts=4,
                email_executions=4,
                disclosures=3,
            ),
            "authorization": make_mode_metrics(
                completed_asr=0.0,
                lookup_attempts=10,
                lookup_executions=0,
                email_attempts=8,
                email_executions=0,
                disclosures=0,
            ),
            "layered": make_mode_metrics(
                completed_asr=0.0,
                lookup_attempts=4,
                lookup_executions=0,
                email_attempts=2,
                email_executions=0,
                disclosures=0,
            ),
        },
        "categories": {
            "workflow_hijacking": {
                "baseline": {
                    "completed_attack_success_rate": 0.9
                },
                "prompt_guard": {
                    "completed_attack_success_rate": 0.4
                },
                "authorization": {
                    "completed_attack_success_rate": 0.0
                },
                "layered": {
                    "completed_attack_success_rate": 0.0
                },
            },
            "instruction_override": {
                "baseline": {
                    "completed_attack_success_rate": 1.0
                },
                "prompt_guard": {
                    "completed_attack_success_rate": 0.5
                },
                "authorization": {
                    "completed_attack_success_rate": 0.0
                },
                "layered": {
                    "completed_attack_success_rate": 0.0
                },
            },
        },
    }


# ============================================================
# Ordering and labels
# ============================================================


def test_four_defense_mode_order():
    modes = {
        "layered",
        "baseline",
        "authorization",
        "prompt_guard",
    }

    assert mode_order(modes) == [
        "baseline",
        "prompt_guard",
        "authorization",
        "layered",
    ]


def test_legacy_mode_order():
    assert mode_order(
        {
            "defended",
            "baseline",
        }
    ) == [
        "baseline",
        "defended",
    ]


def test_display_mode_labels():
    assert (
        display_mode("baseline")
        == "Baseline"
    )

    assert (
        display_mode("prompt_guard")
        == "Prompt Guard"
    )

    assert (
        display_mode("authorization")
        == "Authorization"
    )

    assert (
        display_mode("layered")
        == "Layered"
    )


def test_unknown_display_mode():
    assert (
        display_mode("custom_defense")
        == "Custom Defense"
    )


# ============================================================
# Report loading
# ============================================================


def test_load_report(tmp_path):
    path = (
        tmp_path
        / "report.json"
    )

    report = make_report()

    path.write_text(
        json.dumps(report),
        encoding="utf-8",
    )

    loaded = load_report(
        path
    )

    assert loaded == report


def test_load_report_requires_overall(
    tmp_path,
):
    path = (
        tmp_path
        / "report.json"
    )

    path.write_text(
        json.dumps(
            {
                "categories": {},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="overall",
    ):
        load_report(
            path
        )


def test_load_report_requires_categories(
    tmp_path,
):
    path = (
        tmp_path
        / "report.json"
    )

    path.write_text(
        json.dumps(
            {
                "overall": {},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="categories",
    ):
        load_report(
            path
        )


# ============================================================
# Individual charts
# ============================================================


def test_attack_success_chart_created(
    tmp_path,
):
    output = (
        tmp_path
        / "attack_success.png"
    )

    save_attack_success_chart(
        make_report(),
        output,
    )

    assert output.exists()

    assert (
        output.stat().st_size
        > 0
    )


def test_security_events_chart_created(
    tmp_path,
):
    output = (
        tmp_path
        / "security_events.png"
    )

    save_security_events_chart(
        make_report(),
        output,
    )

    assert output.exists()

    assert (
        output.stat().st_size
        > 0
    )


def test_category_asr_chart_created(
    tmp_path,
):
    output = (
        tmp_path
        / "category_asr.png"
    )

    save_category_asr_chart(
        make_report(),
        output,
    )

    assert output.exists()

    assert (
        output.stat().st_size
        > 0
    )


# ============================================================
# Full visualization generation
# ============================================================


def test_generate_visualizations(
    tmp_path,
):
    source = (
        tmp_path
        / "experiment_report.json"
    )

    report = make_report()

    source.write_text(
        json.dumps(report),
        encoding="utf-8",
    )

    outputs = (
        generate_visualizations(
            report,
            source,
        )
    )

    assert set(
        outputs
    ) == {
        "attack_success",
        "security_events",
        "category_asr",
    }

    for output in (
        outputs.values()
    ):
        assert output.exists()

        assert (
            output.stat().st_size
            > 0
        )


def test_report_suffix_removed_from_output_name(
    tmp_path,
):
    source = (
        tmp_path
        / "benchmark_report.json"
    )

    outputs = (
        generate_visualizations(
            make_report(),
            source,
        )
    )

    assert (
        outputs[
            "attack_success"
        ].name
        == "benchmark_attack_success.png"
    )

    assert (
        outputs[
            "security_events"
        ].name
        == "benchmark_security_events.png"
    )

    assert (
        outputs[
            "category_asr"
        ].name
        == "benchmark_category_asr.png"
    )