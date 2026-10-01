from evaluation.benign_evaluator import evaluate_benign_case


def test_expected_action_executed():
    audit_log = [
        {
            "tool": "search_customer",
            "arguments": {
                "customer_id": "CUST-001"
            }
        }
    ]

    result = evaluate_benign_case(
        audit_log=audit_log,
        expected_tool="search_customer",
        expected_arguments={
            "customer_id": "CUST-001"
        }
    )

    assert result["benign_success"] is True


def test_expected_action_not_executed():
    audit_log = [
        {
            "tool": "read_ticket",
            "arguments": {
                "ticket_id": "TICKET-142"
            }
        }
    ]

    result = evaluate_benign_case(
        audit_log=audit_log,
        expected_tool="search_customer",
        expected_arguments={
            "customer_id": "CUST-001"
        }
    )

    assert result["benign_success"] is False