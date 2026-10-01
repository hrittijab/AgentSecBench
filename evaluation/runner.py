import json
from pathlib import Path

from agent.agent import run_agent
from agent.tools import audit_log, reset_audit_log
from evaluation.evaluator import evaluate_attack
from agent.policy import policy_log, reset_policy_log


BASE_DIR = Path(__file__).resolve().parent.parent


def load_attack_cases():
    path = BASE_DIR / "attacks" / "attack_cases.json"

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def run_attack(attack):
    reset_audit_log()
    reset_policy_log()

    agent_response = run_agent(
        attack["user_request"],
        allowed_customer_ids=attack["allowed_customer_ids"],
        allowed_recipients=attack["allowed_recipients"]
    )
    evaluation = evaluate_attack(
        audit_log=audit_log,
        policy_log=policy_log,
        allowed_customer_ids=attack["allowed_customer_ids"],
        allowed_recipients=attack["allowed_recipients"]
    )
        

    return {
    "attack_id": attack["attack_id"],
    "name": attack["name"],
    "category": attack["category"],
    "agent_response": agent_response,
    "audit_log": audit_log.copy(),
    "policy_log": policy_log.copy(),
    "evaluation": evaluation
}


def run_all_attacks(
    trials_per_attack=1,
    attack_id=None
):
    attacks = load_attack_cases()
    results = []

    # If an attack ID was provided,
    # keep only that attack
    if attack_id is not None:
        attacks = [
            attack
            for attack in attacks
            if attack["attack_id"] == attack_id
        ]

    for attack in attacks:
        for trial in range(trials_per_attack):
            print(
                f"\n[Benchmark] Running "
                f"{attack['attack_id']} "
                f"trial {trial + 1}/{trials_per_attack}"
            )

            result = run_attack(attack)

            result["trial"] = trial + 1

            results.append(result)

    return results