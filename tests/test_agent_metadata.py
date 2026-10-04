
from unittest.mock import patch

from agent.agent import run_agent


def test_default_return_stays_string():
    response = {
        "message": {
            "role": "assistant",
            "content": "Task complete.",
            "tool_calls": []
        },
        "done_reason": "stop",
        "eval_count": 20,
        "prompt_eval_count": 50
    }

    with patch(
        "agent.agent.ollama.chat",
        return_value=response
    ):
        result = run_agent("Test request")

    assert result == "Task complete."
    assert isinstance(result, str)


def test_metadata_records_completion():
    response = {
        "message": {
            "role": "assistant",
            "content": "Task complete.",
            "tool_calls": []
        },
        "done_reason": "stop",
        "eval_count": 20,
        "prompt_eval_count": 50
    }

    with patch(
        "agent.agent.ollama.chat",
        return_value=response
    ):
        result = run_agent(
            "Test request",
            return_metadata=True
        )

    metadata = result["metadata"]

    assert metadata["status"] == "completed"
    assert metadata["steps_used"] == 1
    assert metadata["truncated"] is False
    assert metadata["model_calls"][0][
        "done_reason"
    ] == "stop"


def test_length_limit_detection():
    response = {
        "message": {
            "role": "assistant",
            "content": "Partial response",
            "tool_calls": []
        },
        "done_reason": "length",
        "eval_count": 512,
        "prompt_eval_count": 50
    }

    with patch(
        "agent.agent.ollama.chat",
        return_value=response
    ):
        result = run_agent(
            "Test request",
            return_metadata=True
        )

    metadata = result["metadata"]

    assert metadata["status"] == "truncated"
    assert metadata["truncated"] is True
    assert metadata[
        "truncation_suspected"
    ] is True


def test_max_steps_detection():
    response = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": "read_ticket",
                        "arguments": {
                            "ticket_id": "TICKET-142"
                        }
                    }
                }
            ]
        },
        "done_reason": "stop",
        "eval_count": 20,
        "prompt_eval_count": 50
    }

    with patch(
        "agent.agent.ollama.chat",
        return_value=response
    ), patch(
        "agent.agent.AVAILABLE_TOOLS",
        {
            "read_ticket": lambda ticket_id: {
                "status": "ok"
            }
        }
    ), patch(
        "agent.agent.authorize_tool_call",
        return_value=True
    ):
        result = run_agent(
            "Test request",
            return_metadata=True
        )

    assert result["metadata"]["status"] == "max_steps"
    assert result["metadata"]["steps_used"] == 5
