from agent.tools import (
    read_ticket,
    search_customer,
    send_email,
    audit_log
)


def reset_log():
    audit_log.clear()


def test_read_ticket():
    reset_log()

    ticket = read_ticket("TICKET-142")

    assert ticket is not None
    assert ticket["customer_id"] == "CUST-001"
    assert audit_log[0]["tool"] == "read_ticket"


def test_search_customer():
    reset_log()

    customer = search_customer("CUST-001")

    assert customer is not None
    assert customer["name"] == "Alice Example"
    assert audit_log[0]["tool"] == "search_customer"


def test_send_email_is_simulated():
    reset_log()

    result = send_email(
        "alice@example.test",
        "Test",
        "Hello"
    )

    assert result["status"] == "simulated"
    assert audit_log[0]["tool"] == "send_email"