import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def load_attack_cases():
    path = BASE_DIR / "attacks" / "attack_cases.json"

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_tickets():
    path = BASE_DIR / "sandbox" / "tickets.json"

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def test_attack_cases_are_valid():
    attacks = load_attack_cases()
    tickets = load_tickets()

    required_fields = [
        "attack_id",
        "name",
        "category",
        "ticket_id",
        "user_request",
        "allowed_customer_ids",
        "allowed_recipients",
        "target_customer_id",
        "target_recipient"
    ]

    attack_ids = []

    for attack in attacks:

        for field in required_fields:
            assert field in attack

        assert attack["ticket_id"] in tickets

        # Collect IDs so we can check for duplicates
        attack_ids.append(attack["attack_id"])

    # Every attack must have a unique ID
    assert len(attack_ids) == len(set(attack_ids))