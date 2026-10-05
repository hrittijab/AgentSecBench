import csv

from evaluation.report import (
    export_overall_csv,
    export_categories_csv,
)


def sample_metrics():
    return {
        "trials": 10,
        "statuses": {
            "completed": 9,
            "truncated": 1,
        },
        "completed": 9,
        "legacy_unverified": 0,
        "observed_attack_successes": 5,
        "observed_attack_success_rate": 0.5,
        "completed_attack_successes": 5,
        "completed_attack_success_rate": 0.5556,
        "errors": 0,
        "truncated": 1,
        "timeouts": 0,
        "security": {
            "unauthorized_lookup_attempts": 4,
            "unauthorized_lookup_executions": 4,
            "unauthorized_email_attempts": 2,
            "unauthorized_email_executions": 2,
            "blocked_lookup_calls": 0,
            "blocked_email_calls": 0,
        },
        "disclosure": {
            "trials_with_matched_disclosure": 2,
            "matched_customer_recipient_pairs": 2,
            "customer_counts": {},
            "recipient_counts": {},
        },
    }


def test_export_overall_csv(tmp_path):
    report = {
        "overall": {
            "baseline": sample_metrics(),
            "defended": sample_metrics(),
        },
        "categories": {},
    }

    path = tmp_path / "summary.csv"

    export_overall_csv(report, path)

    assert path.exists()

    with path.open(
        encoding="utf-8",
        newline=""
    ) as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 2
    assert rows[0]["mode"] == "baseline"
    assert rows[1]["mode"] == "defended"

    assert (
        rows[0]["completed_attack_success_rate"]
        == "0.5556"
    )

    assert (
        rows[0]["unauthorized_lookup_executions"]
        == "4"
    )


def test_export_categories_csv(tmp_path):
    report = {
        "overall": {},
        "categories": {
            "workflow_hijacking": {
                "baseline": sample_metrics(),
                "defended": sample_metrics(),
            },
            "encoded_payload": {
                "baseline": sample_metrics(),
            },
        },
    }

    path = tmp_path / "categories.csv"

    export_categories_csv(report, path)

    assert path.exists()

    with path.open(
        encoding="utf-8",
        newline=""
    ) as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 3

    assert rows[0]["category"] == (
        "workflow_hijacking"
    )

    assert rows[0]["mode"] == "baseline"

    assert (
        rows[0]["trials_with_matched_disclosure"]
        == "2"
    )