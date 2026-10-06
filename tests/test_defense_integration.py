from unittest.mock import patch

import pytest

from agent.agent import run_agent


def _final_response():
    return {
        "message": {
            "content": "Done.",
            "tool_calls": [],
        },
        "done_reason": "stop",
        "eval_count": 10,
        "prompt_eval_count": 20,
    }


@pytest.mark.parametrize(
    ("defense", "expected_metadata"),
    [
        ("baseline", "baseline"),
        ("authorization", "authorization"),
        ("prompt_guard", "prompt_guard"),
        ("layered", "layered"),
    ],
)
def test_defense_name_recorded_in_metadata(
    defense,
    expected_metadata,
):
    with patch(
        "agent.agent.ollama.chat",
        return_value=_final_response(),
    ):
        result = run_agent(
            "Test request",
            defense=defense,
            return_metadata=True,
        )

    assert result["metadata"]["defense"] == expected_metadata


def test_prompt_guard_is_added_to_system_prompt():
    captured_messages = None

    def fake_chat(**kwargs):
        nonlocal captured_messages
        captured_messages = kwargs["messages"]
        return _final_response()

    with patch(
        "agent.agent.ollama.chat",
        side_effect=fake_chat,
    ):
        run_agent(
            "Test request",
            defense="prompt_guard",
        )

    system_prompt = captured_messages[0]["content"]

    assert "untrusted" in system_prompt.lower()
    assert "authorization" in system_prompt.lower()


def test_baseline_does_not_receive_prompt_guard():
    captured_messages = None

    def fake_chat(**kwargs):
        nonlocal captured_messages
        captured_messages = kwargs["messages"]
        return _final_response()

    with patch(
        "agent.agent.ollama.chat",
        side_effect=fake_chat,
    ):
        run_agent(
            "Test request",
            defense="baseline",
        )

    system_prompt = captured_messages[0]["content"]

    assert "untrusted task data" not in system_prompt.lower()


def test_authorization_does_not_receive_prompt_guard():
    captured_messages = None

    def fake_chat(**kwargs):
        nonlocal captured_messages
        captured_messages = kwargs["messages"]
        return _final_response()

    with patch(
        "agent.agent.ollama.chat",
        side_effect=fake_chat,
    ):
        run_agent(
            "Test request",
            defense="authorization",
        )

    system_prompt = captured_messages[0]["content"]

    assert "untrusted task data" not in system_prompt.lower()


def test_layered_receives_prompt_guard():
    captured_messages = None

    def fake_chat(**kwargs):
        nonlocal captured_messages
        captured_messages = kwargs["messages"]
        return _final_response()

    with patch(
        "agent.agent.ollama.chat",
        side_effect=fake_chat,
    ):
        run_agent(
            "Test request",
            defense="layered",
        )

    system_prompt = captured_messages[0]["content"]

    assert "untrusted" in system_prompt.lower()


def test_defense_argument_overrides_legacy_enforce_policy():
    """
    The explicit defense strategy must be authoritative.

    baseline should remain baseline even if the legacy caller
    passes enforce_policy=True.
    """

    with patch(
        "agent.agent.ollama.chat",
        return_value=_final_response(),
    ):
        result = run_agent(
            "Test request",
            enforce_policy=True,
            defense="baseline",
            return_metadata=True,
        )

    assert result["metadata"]["defense"] == "baseline"


def test_legacy_baseline_interface_still_works():
    with patch(
        "agent.agent.ollama.chat",
        return_value=_final_response(),
    ):
        result = run_agent(
            "Test request",
            enforce_policy=False,
            return_metadata=True,
        )

    assert result["metadata"]["defense"] == "baseline"


def test_legacy_authorization_interface_still_works():
    with patch(
        "agent.agent.ollama.chat",
        return_value=_final_response(),
    ):
        result = run_agent(
            "Test request",
            enforce_policy=True,
            return_metadata=True,
        )

    assert result["metadata"]["defense"] == "authorization"


def test_unknown_defense_rejected_before_model_call():
    with patch(
        "agent.agent.ollama.chat",
    ) as mock_chat:

        with pytest.raises(
            ValueError,
            match="Unknown defense",
        ):
            run_agent(
                "Test request",
                defense="not-real",
            )

    mock_chat.assert_not_called()