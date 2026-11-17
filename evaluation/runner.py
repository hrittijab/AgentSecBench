
import json
from pathlib import Path

from agent.agent import run_agent
from agent.tools import audit_log, reset_audit_log
from agent.policy import policy_log, reset_policy_log
from evaluation.evaluator import evaluate_attack


BASE_DIR = Path(__file__).resolve().parent.parent

DEFENSE_MODES = [
    "baseline",
    "authorization",
    "prompt_guard",
    "layered",
    "ml_only",
    "ml_layered",
]


def load_attack_cases():
    path = BASE_DIR / "attacks" / "attack_cases.json"

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def run_attack(
    attack,
    enforce_policy=True,
    defense=None,
):
    reset_audit_log()
    reset_policy_log()

    agent_result = run_agent(
        attack["user_request"],
        allowed_customer_ids=attack["allowed_customer_ids"],
        allowed_recipients=attack["allowed_recipients"],
        enforce_policy=enforce_policy,
        defense=defense,
        return_metadata=True,
    )

    evaluation = evaluate_attack(
        audit_log=audit_log,
        policy_log=policy_log,
        allowed_customer_ids=attack["allowed_customer_ids"],
        allowed_recipients=attack["allowed_recipients"],
    )

    return {
        "attack_id": attack["attack_id"],
        "name": attack["name"],
        "category": attack["category"],
        "defense": agent_result["metadata"]["defense"],
        "agent_response": agent_result["content"],
        "metadata": agent_result["metadata"],
        "audit_log": audit_log.copy(),
        "policy_log": policy_log.copy(),
        "evaluation": evaluation,
    }


def run_all_attacks(
    trials_per_attack=1,
    attack_id=None,
    enforce_policy=True,
    defense=None,
):
    attacks = load_attack_cases()
    results = []

    if attack_id is not None:
        attacks = [
            attack
            for attack in attacks
            if attack["attack_id"] == attack_id
        ]

        if not attacks:
            raise ValueError(
                f"Unknown attack ID: {attack_id}"
            )

    for attack in attacks:
        for trial in range(trials_per_attack):
            print(
                f"\n[Benchmark] Running "
                f"{attack['attack_id']} "
                f"trial {trial + 1}/{trials_per_attack}"
                f" | defense={defense}"
            )

            result = run_attack(
                attack,
                enforce_policy=enforce_policy,
                defense=defense,
            )

            result["trial"] = trial + 1
            results.append(result)

    return results


def run_defense_comparison(
    trials_per_attack=1,
    attack_id=None,
    defenses=None,
):
    if defenses is None:
        defenses = DEFENSE_MODES

    results = []

    for defense in defenses:
        if defense not in DEFENSE_MODES:
            raise ValueError(
                f"Unknown defense: {defense}"
            )

        print(
            f"\n{'=' * 55}\n"
            f"DEFENSE: {defense}\n"
            f"{'=' * 55}"
        )

        defense_results = run_all_attacks(
            trials_per_attack=trials_per_attack,
            attack_id=attack_id,
            defense=defense,
        )

        results.extend(defense_results)

    return results
