"""Unified command-line interface for AgentSecBench."""

import argparse
import subprocess
import sys


COMMAND_MODULES = {
    "run": "evaluation.generated_runner",
    "benign": "evaluation.benign_runner",
    "validate": "evaluation.validator",
    "report": "evaluation.report",
    "visualize": "evaluation.visualize",
    "manifest": "evaluation.manifest",
}


DEFENSE_CHOICES = [
    "baseline",
    "prompt_guard",
    "authorization",
    "layered",
]


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
    # Run attack benchmark
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

    run_parser.add_argument(
        "--defenses",
        nargs="+",
        choices=DEFENSE_CHOICES,
        help=(
            "Defense strategies to evaluate. "
            "If omitted, the runner evaluates all "
            "registered default defenses."
        ),
    )

    # --------------------------------------------------------
    # Benign utility benchmark
    # --------------------------------------------------------

    benign_parser = subparsers.add_parser(
        "benign",
        help=(
            "Run benign utility experiments across "
            "defense strategies."
        ),
    )

    benign_parser.add_argument(
        "--defenses",
        nargs="+",
        choices=DEFENSE_CHOICES,
        help=(
            "Defense strategies to evaluate. "
            "If omitted, all default defenses "
            "are evaluated."
        ),
    )

    benign_parser.add_argument(
        "--output",
        help=(
            "Optional path for the benign benchmark "
            "JSON artifact."
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

    # --------------------------------------------------------
    # Attack benchmark arguments
    # --------------------------------------------------------

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

        if args.defenses:
            command_args.append(
                "--defenses"
            )

            command_args.extend(
                args.defenses
            )

    # --------------------------------------------------------
    # Benign benchmark arguments
    # --------------------------------------------------------

    elif args.command == "benign":
        if args.defenses:
            command_args.append(
                "--defenses"
            )

            command_args.extend(
                args.defenses
            )

        if args.output:
            command_args.extend(
                [
                    "--output",
                    args.output,
                ]
            )

    # --------------------------------------------------------
    # Validator arguments
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Report arguments
    # --------------------------------------------------------

    elif args.command == "report":
        command_args.extend(
            [
                "--input",
                args.input,
            ]
        )

    # --------------------------------------------------------
    # Visualization arguments
    # --------------------------------------------------------

    elif args.command == "visualize":
        command_args.extend(
            [
                "--input",
                args.input,
            ]
        )

    # --------------------------------------------------------
    # Manifest arguments
    # --------------------------------------------------------

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
        COMMAND_MODULES[
            args.command
        ],
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