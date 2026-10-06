from evaluation.benign_runner import (
    normalize_defense,
    summarize_benign_results,
    calculate_utility_change,
)


def make_result(
    defense,
    success,
):
    return {
        "case_id": "TEST-001",
        "defense": defense,
        "mode": defense,
        "evaluation": {
            "benign_success": success
        },
    }


def test_normalize_named_defenses():
    assert (
        normalize_defense(
            defense="baseline"
        )
        == "baseline"
    )

    assert (
        normalize_defense(
            defense="prompt_guard"
        )
        == "prompt_guard"
    )

    assert (
        normalize_defense(
            defense="authorization"
        )
        == "authorization"
    )

    assert (
        normalize_defense(
            defense="layered"
        )
        == "layered"
    )


def test_legacy_policy_mapping():
    assert (
        normalize_defense(
            enforce_policy=False
        )
        == "baseline"
    )

    assert (
        normalize_defense(
            enforce_policy=True
        )
        == "authorization"
    )


def test_default_preserves_old_behavior():
    assert (
        normalize_defense()
        == "authorization"
    )


def test_cannot_mix_new_and_legacy_interfaces():
    try:
        normalize_defense(
            defense="layered",
            enforce_policy=True,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Expected ValueError"
        )


def test_benign_summary_by_defense():
    results = [
        make_result(
            "baseline",
            True,
        ),
        make_result(
            "baseline",
            False,
        ),
        make_result(
            "prompt_guard",
            True,
        ),
        make_result(
            "prompt_guard",
            True,
        ),
        make_result(
            "authorization",
            True,
        ),
        make_result(
            "authorization",
            False,
        ),
        make_result(
            "layered",
            True,
        ),
        make_result(
            "layered",
            True,
        ),
    ]

    summaries = summarize_benign_results(
        results
    )

    assert summaries["baseline"][
        "trials"
    ] == 2

    assert summaries["baseline"][
        "successful"
    ] == 1

    assert summaries["baseline"][
        "failed"
    ] == 1

    assert summaries["baseline"][
        "utility_rate"
    ] == 0.5

    assert summaries["prompt_guard"][
        "utility_rate"
    ] == 1.0

    assert summaries["authorization"][
        "utility_rate"
    ] == 0.5

    assert summaries["layered"][
        "utility_rate"
    ] == 1.0


def test_utility_change_vs_baseline():
    summaries = {
        "baseline": {
            "trials": 10,
            "successful": 8,
            "failed": 2,
            "utility_rate": 0.8,
        },
        "prompt_guard": {
            "trials": 10,
            "successful": 7,
            "failed": 3,
            "utility_rate": 0.7,
        },
        "authorization": {
            "trials": 10,
            "successful": 8,
            "failed": 2,
            "utility_rate": 0.8,
        },
        "layered": {
            "trials": 10,
            "successful": 6,
            "failed": 4,
            "utility_rate": 0.6,
        },
    }

    comparison = calculate_utility_change(
        summaries
    )

    assert (
        comparison["prompt_guard"][
            "utility_change_vs_baseline"
        ]
        == -0.1
    )

    assert (
        comparison["authorization"][
            "utility_change_vs_baseline"
        ]
        == 0.0
    )

    assert (
        comparison["layered"][
            "utility_change_vs_baseline"
        ]
        == -0.2
    )


def test_no_baseline_has_no_comparison():
    summaries = {
        "authorization": {
            "trials": 1,
            "successful": 1,
            "failed": 0,
            "utility_rate": 1.0,
        }
    }

    assert (
        calculate_utility_change(
            summaries
        )
        == {}
    )