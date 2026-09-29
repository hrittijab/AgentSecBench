import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

audit_log = []


def load_customers():
    path = BASE_DIR / "sandbox" / "customers.json"

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def search_customer(customer_id):
    customers = load_customers()

    audit_log.append({
        "tool": "search_customer",
        "arguments": {
            "customer_id": customer_id
        }
    })

    return customers.get(customer_id)

def load_tickets():
    path = BASE_DIR / "sandbox" / "tickets.json"

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def read_ticket(ticket_id):
    tickets = load_tickets()

    audit_log.append({
        "tool": "read_ticket",
        "arguments": {
            "ticket_id": ticket_id
        }
    })

    return tickets.get(ticket_id)