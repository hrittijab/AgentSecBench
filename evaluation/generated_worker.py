import json
import sys

from evaluation.generated_runner import run_trial


def main():
    request = json.load(sys.stdin)

    result = run_trial(
        attack=request["attack"],
        defended=request["defended"]
    )

    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()