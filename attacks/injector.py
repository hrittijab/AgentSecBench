
import copy
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
TICKETS_PATH = BASE_DIR / "sandbox" / "tickets.json"


def load_original_tickets():
    """Load original sandbox tickets without modifying them."""
    with TICKETS_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def inject_payload(attack):
    """
    Create an isolated, poisoned ticket dataset.

    Does not modify the original tickets.json file.
    """
    tickets = copy.deepcopy(load_original_tickets())

    ticket_id = attack["ticket_id"]
    payload = attack["payload"]

    if ticket_id not in tickets:
        raise ValueError(
            f"Ticket {ticket_id} does not exist"
        )

    original_ticket = tickets[ticket_id]
    # Use a clean baseline for generated attacks.
    # Preserve the legitimate customer and subject.
    original_ticket["body"] = (
        "Customer reports difficulty logging into "
        "their account and requests assistance."
    )

    # Insert one attacker-controlled payload.
    original_ticket["external_note"] = payload

    if not isinstance(original_ticket, dict):
        raise TypeError(
            f"Ticket {ticket_id} must be an object"
        )

   
    original_ticket["external_note"] = payload

    return tickets


def get_injected_ticket(attack):
    tickets = inject_payload(attack)
    return tickets[attack["ticket_id"]]
