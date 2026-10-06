import sys

import pytest

import cli


# ============================================================
# Attack benchmark CLI
# ============================================================


def test_run_forwards_all_defenses(monkeypatch):
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "run",
            "--defenses",
            "baseline",
            "prompt_guard",
            "authorization",
            "layered",
        ],
    )

    result = cli.main()

    assert result == 0

    command = captured["command"]

    assert (
        "evaluation.generated_runner"
        in command
    )

    assert "--defenses" in command

    assert command[
        command.index("--defenses") + 1:
    ] == [
        "baseline",
        "prompt_guard",
        "authorization",
        "layered",
    ]


def test_run_forwards_selected_defenses(
    monkeypatch,
):
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "run",
            "--defenses",
            "baseline",
            "layered",
        ],
    )

    result = cli.main()

    assert result == 0

    command = captured["command"]

    assert command[-3:] == [
        "--defenses",
        "baseline",
        "layered",
    ]


def test_run_forwards_limit_and_timeout(
    monkeypatch,
):
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "run",
            "--limit",
            "10",
            "--timeout",
            "45",
            "--defenses",
            "baseline",
            "authorization",
        ],
    )

    result = cli.main()

    assert result == 0

    command = captured["command"]

    assert "--limit" in command
    assert "--timeout" in command
    assert "--defenses" in command

    assert (
        command[
            command.index("--limit") + 1
        ]
        == "10"
    )

    assert (
        command[
            command.index("--timeout") + 1
        ]
        == "45"
    )


def test_run_without_defenses_preserves_runner_defaults(
    monkeypatch,
):
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "run",
        ],
    )

    result = cli.main()

    assert result == 0

    assert captured["command"] == [
        sys.executable,
        "-m",
        "evaluation.generated_runner",
    ]


def test_run_invalid_defense_rejected(
    monkeypatch,
):
    called = False

    def fake_run(command, check=False):
        nonlocal called
        called = True

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "run",
            "--defenses",
            "fake_defense",
        ],
    )

    with pytest.raises(
        SystemExit
    ) as exc_info:
        cli.main()

    assert exc_info.value.code == 2
    assert called is False


# ============================================================
# Existing command routing
# ============================================================


def test_validate_dispatches(
    monkeypatch,
):
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "validate",
            "--input",
            "results/test.json",
        ],
    )

    result = cli.main()

    assert result == 0

    assert (
        "evaluation.validator"
        in captured["command"]
    )

    assert "--input" in captured["command"]


def test_report_dispatches(
    monkeypatch,
):
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "report",
            "--input",
            "results/test.json",
        ],
    )

    result = cli.main()

    assert result == 0

    assert (
        "evaluation.report"
        in captured["command"]
    )


def test_visualize_dispatches(
    monkeypatch,
):
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "visualize",
            "--input",
            "results/report.json",
        ],
    )

    result = cli.main()

    assert result == 0

    assert (
        "evaluation.visualize"
        in captured["command"]
    )


# ============================================================
# Benign benchmark CLI
# ============================================================


def test_benign_forwards_all_defenses(
    monkeypatch,
):
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "benign",
            "--defenses",
            "baseline",
            "prompt_guard",
            "authorization",
            "layered",
        ],
    )

    result = cli.main()

    assert result == 0

    command = captured["command"]

    assert (
        "evaluation.benign_runner"
        in command
    )

    assert "--defenses" in command

    assert command[
        command.index("--defenses") + 1:
    ] == [
        "baseline",
        "prompt_guard",
        "authorization",
        "layered",
    ]


def test_benign_forwards_selected_defenses(
    monkeypatch,
):
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "benign",
            "--defenses",
            "baseline",
            "layered",
        ],
    )

    result = cli.main()

    assert result == 0

    command = captured["command"]

    assert command[-3:] == [
        "--defenses",
        "baseline",
        "layered",
    ]


def test_benign_forwards_output(
    monkeypatch,
):
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "benign",
            "--output",
            "results/test_benign.json",
        ],
    )

    result = cli.main()

    assert result == 0

    command = captured["command"]

    assert "--output" in command

    output_index = command.index(
        "--output"
    )

    assert (
        command[output_index + 1]
        == "results/test_benign.json"
    )


def test_benign_without_defenses_uses_runner_defaults(
    monkeypatch,
):
    captured = {}

    def fake_run(command, check=False):
        captured["command"] = command

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "benign",
        ],
    )

    result = cli.main()

    assert result == 0

    assert captured["command"] == [
        sys.executable,
        "-m",
        "evaluation.benign_runner",
    ]


def test_benign_invalid_defense_rejected(
    monkeypatch,
):
    called = False

    def fake_run(command, check=False):
        nonlocal called
        called = True

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentsecbench",
            "benign",
            "--defenses",
            "fake_defense",
        ],
    )

    with pytest.raises(
        SystemExit
    ) as exc_info:
        cli.main()

    assert exc_info.value.code == 2
    assert called is False