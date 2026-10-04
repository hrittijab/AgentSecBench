
from copy import deepcopy

from evaluation.validator import (
    validate_experiment,
)


ATTACKS = [
    {
        "attack_id": "TEST-001",
        "category": "workflow_hijacking",
    },
    {
        "attack_id": "TEST-002",
        "category": "encoded_payload",
    },
]


def make_trial(attack_id, mode, category):
    return {
        "attack_id": attack_id,
        "mode": mode,
        "category": category,
        "status": "completed",
        "valid_trial": True,
        "ticket_read": True,
        "error": None,
        "truncated": False,
        "tool_attempts": [],
        "executed_tools": [],
        "policy_decisions": [],
    }


def valid_pair():
    return [
        make_trial(
            "TEST-001",
            "baseline",
            "workflow_hijacking",
        ),
        make_trial(
            "TEST-001",
            "defended",
            "workflow_hijacking",
        ),
    ]


def test_valid_complete_experiment():
    results = valid_pair()

    results.extend([
        make_trial(
            "TEST-002",
            "baseline",
            "encoded_payload",
        ),
        make_trial(
            "TEST-002",
            "defended",
            "encoded_payload",
        ),
    ])

    report = validate_experiment(
        results,
        ATTACKS
    )

    assert report["valid"] is True
    assert report["summary"]["paired_attacks"] == 2


def test_valid_partial_experiment():
    report = validate_experiment(
        valid_pair(),
        ATTACKS,
        allow_partial=True
    )

    assert report["valid"] is True


def test_missing_pair_detected():
    results = valid_pair()[:1]

    report = validate_experiment(
        results,
        ATTACKS,
        allow_partial=True
    )

    assert report["valid"] is False
    assert any(
        "missing paired" in error
        for error in report["errors"]
    )


def test_duplicate_trial_detected():
    results = valid_pair()
    results.append(
        deepcopy(results[0])
    )

    report = validate_experiment(
        results,
        ATTACKS,
        allow_partial=True
    )

    assert report["valid"] is False
    assert any(
        "Duplicate trial" in error
        for error in report["errors"]
    )


def test_category_mismatch_detected():
    results = valid_pair()
    results[0]["category"] = "encoded_payload"

    report = validate_experiment(
        results,
        ATTACKS,
        allow_partial=True
    )

    assert report["valid"] is False
    assert any(
        "category mismatch" in error
        for error in report["errors"]
    )


def test_inconsistent_completion_detected():
    results = valid_pair()
    results[0]["status"] = "truncated"
    results[0]["truncated"] = True

    report = validate_experiment(
        results,
        ATTACKS,
        allow_partial=True
    )

    assert report["valid"] is False
    assert any(
        "conflicts" in error
        for error in report["errors"]
    )


def test_legacy_metadata_warning():
    results = valid_pair()

    for trial in results:
        trial.pop("valid_trial")
        trial.pop("status")

    report = validate_experiment(
        results,
        ATTACKS,
        allow_partial=True
    )

    assert report["valid"] is True
    assert len(report["warnings"]) == 2
