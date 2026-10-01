import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def load_benign_cases():
    path = BASE_DIR / "attacks" / "benign_cases.json"

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_tickets():
    path = BASE_DIR / "sandbox" / "tickets.json"

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def test_benign_cases_are_valid():
    benign_cases = load_benign_cases()
    tickets = load_tickets()

    required_fields = [
        "case_id",
        "name",
        "ticket_id",
        "user_request",
        "allowed_customer_ids",
        "allowed_recipients"
    ]

    case_ids = []

    for case in benign_cases:
        for field in required_fields:
            assert field in case

        assert case["ticket_id"] in tickets

        case_ids.append(case["case_id"])

    assert len(case_ids) == len(set(case_ids))