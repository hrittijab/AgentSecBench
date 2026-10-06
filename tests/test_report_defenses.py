from evaluation.report import build_defense_comparison


def metrics(
    observed_rate,
    completed_rate,
    lookup_attempts=0,
    lookup_executions=0,
    email_attempts=0,
    email_executions=0,
    blocked_lookup=0,
    blocked_email=0,
    disclosure=0,
):
    return {
        "observed_attack_success_rate": observed_rate,
        "completed_attack_success_rate": completed_rate,
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
            "blocked_lookup_calls": blocked_lookup,
            "blocked_email_calls": blocked_email,
        },
        "disclosure": {
            "trials_with_matched_disclosure": (
                disclosure
            ),
            "matched_customer_recipient_pairs": (
                disclosure
            ),
        },
    }


def test_four_defense_comparison():
    overall = {
        "baseline": metrics(
            0.50,
            0.60,
            lookup_executions=10,
            email_executions=5,
            disclosure=5,
        ),
        "prompt_guard": metrics(
            0.30,
            0.40,
            lookup_executions=6,
            email_executions=3,
            disclosure=3,
        ),
        "authorization": metrics(
            0.0,
            0.0,
            lookup_attempts=10,
            blocked_lookup=10,
        ),
        "layered": metrics(
            0.0,
            0.0,
            lookup_attempts=4,
            blocked_lookup=4,
        ),
    }

    comparison = build_defense_comparison(
        overall
    )

    assert set(comparison) == {
        "prompt_guard",
        "authorization",
        "layered",
    }

    assert (
        comparison["prompt_guard"][
            "observed_attack_success_reduction"
        ]
        == 0.20
    )

    assert (
        comparison["prompt_guard"][
            "completed_attack_success_reduction"
        ]
        == 0.20
    )

    assert (
        comparison["authorization"][
            "observed_attack_success_reduction"
        ]
        == 0.50
    )

    assert (
        comparison["authorization"][
            "completed_attack_success_reduction"
        ]
        == 0.60
    )

    assert (
        comparison["layered"][
            "observed_attack_success_reduction"
        ]
        == 0.50
    )


def test_authorization_metrics_preserved():
    overall = {
        "baseline": metrics(
            0.5,
            0.5,
        ),
        "authorization": metrics(
            0.0,
            0.0,
            lookup_attempts=12,
            lookup_executions=0,
            email_attempts=7,
            email_executions=0,
            blocked_lookup=12,
            blocked_email=7,
        ),
    }

    comparison = build_defense_comparison(
        overall
    )

    authorization = comparison[
        "authorization"
    ]

    assert (
        authorization[
            "unauthorized_lookup_attempts"
        ]
        == 12
    )

    assert (
        authorization[
            "unauthorized_lookup_executions"
        ]
        == 0
    )

    assert (
        authorization[
            "blocked_lookup_calls"
        ]
        == 12
    )

    assert (
        authorization[
            "blocked_email_calls"
        ]
        == 7
    )


def test_prompt_guard_does_not_imply_blocking():
    overall = {
        "baseline": metrics(
            0.5,
            0.5,
        ),
        "prompt_guard": metrics(
            0.25,
            0.25,
            lookup_attempts=4,
            lookup_executions=4,
            blocked_lookup=0,
        ),
    }

    comparison = build_defense_comparison(
        overall
    )

    prompt_guard = comparison[
        "prompt_guard"
    ]

    assert (
        prompt_guard[
            "unauthorized_lookup_executions"
        ]
        == 4
    )

    assert (
        prompt_guard[
            "blocked_lookup_calls"
        ]
        == 0
    )


def test_no_baseline_returns_empty_comparison():
    overall = {
        "authorization": metrics(
            0.0,
            0.0,
        ),
    }

    assert (
        build_defense_comparison(overall)
        == {}
    )


def test_missing_completed_rate_is_supported():
    overall = {
        "baseline": metrics(
            0.5,
            None,
        ),
        "layered": metrics(
            0.0,
            None,
        ),
    }

    comparison = build_defense_comparison(
        overall
    )

    assert (
        comparison["layered"][
            "observed_attack_success_reduction"
        ]
        == 0.5
    )

    assert (
        comparison["layered"][
            "completed_attack_success_reduction"
        ]
        is None
    )