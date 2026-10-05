"""Regression tests for safe agent tool dispatch."""

from unittest.mock import patch

from agent.agent import run_agent
from agent.policy import policy_log, reset_policy_log
from agent.tools import audit_log, reset_audit_log


def make_response(
    *,
    tool_name=None,
    arguments=None,
    content="",
):
    if tool_name is None:
        tool_calls = []
    else:
        tool_calls = [
            {
                "function": {
                    "name": tool_name,
                    "arguments": arguments,
                }
            }
        ]

    return {
        "message": {
            "role": "assistant",
            "content": content,
            "tool_calls": tool_calls,
        },
        "done_reason": "stop",
        "eval_count": 20,
        "prompt_eval_count": 50,
    }


def setup_function():
    reset_policy_log()
    reset_audit_log()


def teardown_function():
    reset_policy_log()
    reset_audit_log()


@patch("agent.agent.ollama.chat")
def test_unknown_tool_does_not_crash_baseline(mock_chat):
    mock_chat.side_effect = [
        make_response(
            tool_name="delete_customer",
            arguments={"customer_id": "CUST-001"},
        ),
        make_response(content="Unable to perform action."),
    ]

    result = run_agent(
        "Delete CUST-001.",
        enforce_policy=False,
    )

    assert result == "Unable to perform action."
    assert audit_log == []
    assert mock_chat.call_count == 2


@patch("agent.agent.ollama.chat")
def test_unknown_tool_rejected_in_defended_mode(mock_chat):
    mock_chat.side_effect = [
        make_response(
            tool_name="delete_customer",
            arguments={"customer_id": "CUST-001"},
        ),
        make_response(content="Unable to perform action."),
    ]

    result = run_agent(
        "Delete CUST-001.",
        enforce_policy=True,
    )

    assert result == "Unable to perform action."

    # Unknown tools must never reach sandbox execution.
    assert audit_log == []

    # Unknown tools are rejected by dispatch validation
    # before the authorization policy is consulted.
    assert policy_log == []

    # The agent should recover and continue normally.
    assert mock_chat.call_count == 2

@patch("agent.agent.ollama.chat")
def test_missing_tool_arguments_do_not_crash_baseline(mock_chat):
    mock_chat.side_effect = [
        make_response(
            tool_name="search_customer",
            arguments={},
        ),
        make_response(content="Unable to search."),
    ]

    result = run_agent(
        "Search for the customer.",
        enforce_policy=False,
    )

    assert result == "Unable to search."

    assert not any(
        entry["tool"] == "search_customer"
        for entry in audit_log
    )


@patch("agent.agent.ollama.chat")
def test_extra_tool_arguments_do_not_crash(mock_chat):
    mock_chat.side_effect = [
        make_response(
            tool_name="search_customer",
            arguments={
                "customer_id": "CUST-001",
                "unexpected": "value",
            },
        ),
        make_response(content="Unable to search."),
    ]

    result = run_agent(
        "Search for CUST-001.",
        allowed_customer_ids=["CUST-001"],
        enforce_policy=True,
    )

    assert result == "Unable to search."


@patch("agent.agent.ollama.chat")
def test_tool_exception_does_not_crash_agent(mock_chat):
    mock_chat.side_effect = [
        make_response(
            tool_name="search_customer",
            arguments={"customer_id": "CUST-001"},
        ),
        make_response(content="Search failed safely."),
    ]

    with patch(
        "agent.agent.AVAILABLE_TOOLS",
        {
            **__import__(
                "agent.agent",
                fromlist=["AVAILABLE_TOOLS"]
            ).AVAILABLE_TOOLS,
            "search_customer": lambda **kwargs: (
                (_ for _ in ()).throw(
                    RuntimeError("simulated failure")
                )
            ),
        },
    ):
        result = run_agent(
            "Search CUST-001.",
            allowed_customer_ids=["CUST-001"],
            enforce_policy=True,
        )

    assert result == "Search failed safely."