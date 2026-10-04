
import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

TRACKED_FILES = [
    "agent/agent.py",
    "agent/policy.py",
    "agent/tools.py",
    "attacks/injector.py",
    "attacks/generated_attacks.json",
    "sandbox/customers.json",
    "evaluation/generated_runner.py",
    "evaluation/generated_worker.py",
    "evaluation/security_metrics.py",
    "evaluation/exfiltration.py",
    "evaluation/report.py",
    "evaluation/validator.py",
    "requirements.txt",
]


def sha256_file(path):
    digest = hashlib.sha256()

    with Path(path).open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def run_command(command):
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        return result.stdout.strip()
    except (
        OSError,
        subprocess.SubprocessError
    ):
        return None


def git_information():
    revision = run_command([
        "git", "rev-parse", "HEAD"
    ])

    status = run_command([
        "git", "status", "--porcelain"
    ])

    return {
        "revision": revision,
        "dirty": (
            bool(status)
            if status is not None
            else None
        ),
        "working_tree_changes": (
            status.splitlines()
            if status is not None
            else None
        ),
    }


def ollama_information(model):
    """
    Query the installed Ollama model metadata.

    A model name is not a sufficient
    reproducibility identifier.
    """
    raw = run_command([
        "ollama", "list"
    ])

    if raw is None:
        return {
            "requested_model": model,
            "resolved_model": None,
            "digest": None,
            "available": False,
        }

    lines = raw.splitlines()

    for line in lines[1:]:
        parts = line.split()

        if len(parts) < 2:
            continue

        name = parts[0]
        digest = parts[1]

        if name == model:
            return {
                "requested_model": model,
                "resolved_model": name,
                "digest": digest,
                "available": True,
            }

    return {
        "requested_model": model,
        "resolved_model": None,
        "digest": None,
        "available": False,
    }


def build_manifest(model=None):
    if model is None:
        from agent.agent import (
            MODEL_NAME,
            MAX_OUTPUT_TOKENS,
            MAX_AGENT_STEPS,
        )
        model = MODEL_NAME
    else:
        from agent.agent import (
            MAX_OUTPUT_TOKENS,
            MAX_AGENT_STEPS,
        )

    files = {}

    for relative in TRACKED_FILES:
        path = ROOT / relative

        files[relative] = (
            sha256_file(path)
            if path.is_file()
            else None
        )

    return {
        "schema_version": 1,
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "project": "AgentSecBench",
        "git": git_information(),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
        },
        "agent": {
            "model": model,
            "max_output_tokens": (
                MAX_OUTPUT_TOKENS
            ),
            "max_agent_steps": (
                MAX_AGENT_STEPS
            ),
        },
        "ollama": ollama_information(model),
        "file_hashes": files,
    }


def verify_manifest(manifest):
    mismatches = []
    missing = []

    for relative, expected in (
        manifest["file_hashes"].items()
    ):
        path = ROOT / relative

        if not path.is_file():
            missing.append(relative)
            continue

        actual = sha256_file(path)

        if expected is None or actual != expected:
            mismatches.append(relative)

    return {
        "valid": (
            not mismatches and not missing
        ),
        "mismatches": mismatches,
        "missing": missing,
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--output",
        default=None
    )

    parser.add_argument(
        "--verify",
        default=None
    )

    parser.add_argument(
        "--model",
        default=None
    )

    args = parser.parse_args()

    if args.verify:
        with open(
            args.verify,
            encoding="utf-8"
        ) as f:
            manifest = json.load(f)

        result = verify_manifest(
            manifest
        )

        print(json.dumps(
            result,
            indent=2
        ))

        if not result["valid"]:
            raise SystemExit(1)

        return

    manifest = build_manifest(
        model=args.model
    )

    output = (
        Path(args.output)
        if args.output
        else ROOT / "results" /
        "experiment_manifest.json"
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output.open(
        "w", encoding="utf-8"
    ) as f:
        json.dump(
            manifest,
            f,
            indent=2
        )

    print("\nAGENTSECBENCH MANIFEST")
    print("=" * 50)

    print(
        "Model:",
        manifest["agent"]["model"]
    )
    print(
        "Ollama digest:",
        manifest["ollama"]["digest"]
    )
    print(
        "Git revision:",
        manifest["git"]["revision"]
    )
    print(
        "Dirty working tree:",
        manifest["git"]["dirty"]
    )
    print(
        "Saved:",
        output
    )


if __name__ == "__main__":
    main()
