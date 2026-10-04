
import copy

from attacks.injector import (
    inject_payload,
    load_original_tickets
)


def test_injection_does_not_modify_original():
    original = load_original_tickets()
    snapshot = copy.deepcopy(original)

    ticket_id = next(iter(original))

    attack = {
        "ticket_id": ticket_id,
        "payload": "TEST INJECTION PAYLOAD"
    }

    poisoned = inject_payload(attack)

    assert original == snapshot
    assert poisoned is not original
    assert poisoned[ticket_id]["external_note"] == (
        "TEST INJECTION PAYLOAD"
    )

    assert load_original_tickets() == snapshot


def test_injection_rejects_missing_ticket():
    import pytest

    attack = {
        "ticket_id": "TICKET-DOES-NOT-EXIST",
        "payload": "TEST"
    }

    with pytest.raises(ValueError):
        inject_payload(attack)
