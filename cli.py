"""Unified command-line interface for AgentSecBench."""

import argparse
import subprocess
import sys


COMMAND_MODULES = {
    "run": "evaluation.generated_runner",
    "validate": "evaluation.validator",
    "report": "evaluation.report",
    "visualize": "evaluation.visualize",
    "manifest": "evaluation.manifest",
}


def main():
    parser = argparse.ArgumentParser(
        prog="agentsecbench",
        description=(
            "Security benchmark for indirect prompt injection "
            "against tool-using AI agents."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # --------------------------------------------------------
    # Run
    # --------------------------------------------------------

    run_parser = subparsers.add_parser(
        "run",
        help="Run generated attack experiments.",
    )

    run_parser.add_argument(
        "--limit",
        type=int,
        help=(
            "Run only the first N generated attacks."
        ),
    )

    run_parser.add_argument(
        "--timeout",
        type=int,
        help=(
            "Maximum execution time in seconds "
            "for each trial."
        ),
    )

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate experiment results.",
    )

    validate_parser.add_argument(
        "--input",
        required=True,
        help="Path to the experiment result JSON.",
    )

    validate_parser.add_argument(
        "--allow-partial",
        action="store_true",
        help=(
            "Allow validation of partial benchmark runs."
        ),
    )

    # --------------------------------------------------------
    # Report
    # --------------------------------------------------------

    report_parser = subparsers.add_parser(
        "report",
        help=(
            "Generate security report and CSV exports."
        ),
    )

    report_parser.add_argument(
        "--input",
        required=True,
        help="Path to the experiment result JSON.",
    )

    # --------------------------------------------------------
    # Visualize
    # --------------------------------------------------------

    visualize_parser = subparsers.add_parser(
        "visualize",
        help=(
            "Generate benchmark visualizations "
            "from a security report."
        ),
    )

    visualize_parser.add_argument(
        "--input",
        required=True,
        help=(
            "Path to an AgentSecBench report JSON."
        ),
    )

    # --------------------------------------------------------
    # Manifest
    # --------------------------------------------------------

    manifest_parser = subparsers.add_parser(
        "manifest",
        help=(
            "Create or verify an experiment manifest."
        ),
    )

    manifest_parser.add_argument(
        "--verify",
        help=(
            "Verify an existing experiment manifest."
        ),
    )

    # --------------------------------------------------------
    # Parse command
    # --------------------------------------------------------

    args = parser.parse_args()

    command_args = []

    if args.command == "run":
        if args.limit is not None:
            command_args.extend(
                [
                    "--limit",
                    str(args.limit),
                ]
            )

        if args.timeout is not None:
            command_args.extend(
                [
                    "--timeout",
                    str(args.timeout),
                ]
            )

    elif args.command == "validate":
        command_args.extend(
            [
                "--input",
                args.input,
            ]
        )

        if args.allow_partial:
            command_args.append(
                "--allow-partial"
            )

    elif args.command == "report":
        command_args.extend(
            [
                "--input",
                args.input,
            ]
        )

    elif args.command == "visualize":
        command_args.extend(
            [
                "--input",
                args.input,
            ]
        )

    elif args.command == "manifest":
        if args.verify:
            command_args.extend(
                [
                    "--verify",
                    args.verify,
                ]
            )

    # --------------------------------------------------------
    # Dispatch
    # --------------------------------------------------------

    command = [
        sys.executable,
        "-m",
        COMMAND_MODULES[args.command],
        *command_args,
    ]

    try:
        result = subprocess.run(
            command,
            check=False,
        )

        return result.returncode

    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())