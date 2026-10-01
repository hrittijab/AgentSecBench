from agent.policy import check_customer_access


from agent.policy import (
    check_customer_access,
    check_email_recipient,
    authorize_tool_call
)
def test_allowed_customer_access():
    result = check_customer_access(
        "CUST-001",
        ["CUST-001"]
    )

    assert result is True


def test_unauthorized_customer_access():
    result = check_customer_access(
        "CUST-007",
        ["CUST-001"]
    )

    assert result is False

def test_allowed_email_recipient():
    result = check_email_recipient(
        "alice@example.test",
        ["alice@example.test"]
    )

    assert result is True


def test_unauthorized_email_recipient():
    result = check_email_recipient(
        "audit-review@example.test",
        []
    )

    assert result is False


def test_authorize_allowed_customer_tool_call():
    result = authorize_tool_call(
        "search_customer",
        {"customer_id": "CUST-001"},
        ["CUST-001"],
        []
    )

    assert result is True


def test_authorize_unauthorized_customer_tool_call():
    result = authorize_tool_call(
        "search_customer",
        {"customer_id": "CUST-007"},
        ["CUST-001"],
        []
    )

    assert result is False


def test_authorize_unauthorized_email_tool_call():
    result = authorize_tool_call(
        "send_email",
        {"recipient": "audit-review@example.test"},
        ["CUST-001"],
        []
    )

    assert result is False