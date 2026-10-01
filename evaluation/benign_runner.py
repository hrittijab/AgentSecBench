import json
from pathlib import Path

from agent.agent import run_agent
from agent.tools import audit_log, reset_audit_log
from agent.policy import policy_log, reset_policy_log
from evaluation.benign_evaluator import evaluate_benign_case


BASE_DIR = Path(__file__).resolve().parent.parent


def load_benign_cases():
    path = BASE_DIR / "attacks" / "benign_cases.json"

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def run_benign_case(case):
    reset_audit_log()
    reset_policy_log()

    agent_response = run_agent(
        case["user_request"],
        allowed_customer_ids=case["allowed_customer_ids"],
        allowed_recipients=case["allowed_recipients"]
    )
    evaluation = evaluate_benign_case(
        audit_log=audit_log,
        expected_tool=case["expected_tool"],
        expected_arguments=case["expected_arguments"]
    )

    return {
        "case_id": case["case_id"],
        "name": case["name"],
        "agent_response": agent_response,
        "audit_log": audit_log.copy(),
        "policy_log": policy_log.copy(),
        "evaluation": evaluation
    }


def run_all_benign_cases():
    cases = load_benign_cases()
    results = []

    for case in cases:
        print(
            f"\n[Benign Benchmark] Running "
            f"{case['case_id']}"
        )

        result = run_benign_case(case)
        results.append(result)

    return results