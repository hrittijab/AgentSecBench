import json
import sys

from evaluation.generated_runner import run_trial


def main():
    request = json.load(sys.stdin)

    attack = request["attack"]

    # New v3 worker interface.
    if "defense" in request:
        result = run_trial(
            attack=attack,
            defense=request["defense"],
        )

    # Backward compatibility with the v2 worker protocol.
    elif "defended" in request:
        result = run_trial(
            attack=attack,
            defended=request["defended"],
        )

    else:
        raise ValueError(
            "Worker request must contain either "
            "'defense' or legacy 'defended'"
        )

    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()