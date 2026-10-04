
import json
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

from agent import agent as agent_module
from evaluation.generated_runner import run_trial


ROOT = Path(__file__).resolve().parent.parent
ATTACKS_PATH = ROOT / "attacks" / "generated_attacks.json"

ATTACK_ID = "GEN-0096"
TIMEOUT = 45
MAX_TOKENS = 256


def diagnose():
    with ATTACKS_PATH.open(
        "r", encoding="utf-8"
    ) as file:
        attacks = json.load(file)

    attack = next(
        item for item in attacks
        if item["attack_id"] == ATTACK_ID
    )

    original_chat = agent_module.ollama.chat
    call_number = 0

    def timed_chat(*args, **kwargs):
        nonlocal call_number

        call_number += 1
        started = time.perf_counter()

        # Inspect conversation messages.
        messages = kwargs.get("messages")

        if messages is None and len(args) >= 2:
            messages = args[1]

        if messages is None:
            messages = []

        sizes = [
            len(str(message))
            for message in messages
        ]

        total_chars = sum(sizes)

        print(
            f"\n--- Model call {call_number} ---",
            file=sys.stderr,
            flush=True
        )

        print(
            f"Messages: {len(messages)}",
            file=sys.stderr,
            flush=True
        )

        print(
            f"Message sizes: {sizes}",
            file=sys.stderr,
            flush=True
        )

        print(
            f"Total message characters: {total_chars}",
            file=sys.stderr,
            flush=True
        )

        print(
            f"Rough message token estimate: "
            f"{total_chars // 4}",
            file=sys.stderr,
            flush=True
        )

        # Limit output only for diagnosis.
        diagnostic_kwargs = dict(kwargs)

        existing_options = (
            diagnostic_kwargs.get("options") or {}
        )

        diagnostic_kwargs["options"] = {
            **dict(existing_options),
            "num_predict": MAX_TOKENS
        }

        print(
            f"Generation limit: {MAX_TOKENS} tokens",
            file=sys.stderr,
            flush=True
        )

        print(
            f"Model call {call_number} started",
            file=sys.stderr,
            flush=True
        )

        try:
            response = original_chat(
                *args,
                **diagnostic_kwargs
            )

            duration = (
                time.perf_counter() - started
            )

            print(
                f"Model call {call_number} finished "
                f"in {duration:.2f}s",
                file=sys.stderr,
                flush=True
            )

            # Inspect tool calls.
            message = response.message

            tool_calls = (
                getattr(message, "tool_calls", None)
                or []
            )

            print(
                f"Tool calls returned: {len(tool_calls)}",
                file=sys.stderr,
                flush=True
            )

            for tool_call in tool_calls:
                print(
                    f"  Tool: {tool_call.function.name}",
                    file=sys.stderr,
                    flush=True
                )

            # Ollama performance metrics.
            metrics = (
                "prompt_eval_count",
                "eval_count",
                "prompt_eval_duration",
                "eval_duration"
            )

            for metric in metrics:
                value = getattr(
                    response, metric, None
                )

                if value is None:
                    continue

                if metric.endswith("_duration"):
                    value = round(
                        value / 1_000_000_000,
                        2
                    )
                    unit = "s"
                else:
                    unit = ""

                print(
                    f"{metric}: {value}{unit}",
                    file=sys.stderr,
                    flush=True
                )

            return response

        except Exception as exc:
            print(
                f"Model call {call_number} failed: "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
                flush=True
            )
            raise

    print(
        f"Diagnosing {ATTACK_ID}...",
        file=sys.stderr,
        flush=True
    )

    with patch.object(
        agent_module.ollama,
        "chat",
        side_effect=timed_chat
    ):
        result = run_trial(
            attack,
            defended=False
        )

    print(
        "\nDiagnostic result:",
        file=sys.stderr,
        flush=True
    )

    print(
        json.dumps({
            "attack_id": result["attack_id"],
            "duration_seconds": result[
                "duration_seconds"
            ],
            "error": result["error"],
            "attack_success": result[
                "attack_success"
            ],
            "tool_attempts": result[
                "tool_attempts"
            ]
        }, indent=2),
        flush=True
    )


def main():
    if "--worker" in sys.argv:
        diagnose()
        return

    print(
        f"Starting diagnostic "
        f"(maximum {TIMEOUT} seconds)...",
        flush=True
    )

    try:
        subprocess.run(
            [
                sys.executable,
                "-u",
                "-m",
                "evaluation.diagnose",
                "--worker"
            ],
            cwd=ROOT,
            timeout=TIMEOUT,
            check=True
        )

    except subprocess.TimeoutExpired:
        print(
            f"\nDiagnostic timed out after "
            f"{TIMEOUT} seconds.",
            flush=True
        )

    except subprocess.CalledProcessError as exc:
        print(
            f"Diagnostic failed: {exc}",
            flush=True
        )


if __name__ == "__main__":
    main()
