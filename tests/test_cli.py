
import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "command",
    ["run", "validate", "report", "manifest"],
)
def test_cli_help(command):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cli",
            command,
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "usage:" in result.stdout.lower()


def test_cli_main_help():
    result = subprocess.run(
        [sys.executable, "-m", "cli", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    for command in ("run", "validate", "report", "manifest"):
        assert command in result.stdout
