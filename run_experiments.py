
import json
from pathlib import Path
from datetime import datetime

from evaluation.runner import load_attack_cases, run_attack
from evaluation.benign_runner import (
    load_benign_cases,
    run_benign_case,
)

TRIALS = 5
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

run_id = datetime.now().strftime("%Y%m%d_%H%M%S")


def save(path, data):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temp.replace(path)


def experiment(cases, mode, kind):
    enforce_policy = mode == "defended"
    path = RESULTS_DIR / f"{mode}_{kind}_{run_id}.json"

    output = {
        "mode": mode,
        "kind": kind,
        "trials_per_case": TRIALS,
        "results": [],
    }

    for case in cases:
        case_id = case.get("attack_id", case.get("case_id"))

        for trial in range(1, TRIALS + 1):
            print(f"{mode} | {case_id} | trial {trial}", flush=True)

            if kind == "attack":
                result = run_attack(
                    case, enforce_policy=enforce_policy
                )
            else:
                result = run_benign_case(
                    case, enforce_policy=enforce_policy
                )

            result["trial"] = trial
            output["results"].append(result)
            save(path, output)

    key = (
        "attack_success"
        if kind == "attack"
        else "benign_success"
    )

    results = output["results"]
    successes = sum(
        bool(r["evaluation"][key])
        for r in results
    )

    output["summary"] = {
        "total_trials": len(results),
        "successes": successes,
        "success_rate": round(
            100 * successes / len(results), 2
        ),
    }

    if kind == "attack":
        blocked = sum(
            bool(r["evaluation"]["blocked_attack_attempt"])
            for r in results
        )
        output["summary"]["blocked_attempt_trials"] = blocked
        output["summary"]["blocked_attempt_rate"] = round(
            100 * blocked / len(results), 2
        )

    save(path, output)
    print(output["summary"])




if __name__ == "__main__":
    attacks = load_attack_cases()
    benign = load_benign_cases()

    experiment(benign, "baseline", "benign")
    experiment(attacks, "defended", "attack")
    experiment(benign, "defended", "benign")
