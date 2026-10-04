
from agent.tools import (
    read_ticket,
    search_customer,
    send_email
)

from agent.policy import authorize_tool_call

import ollama


# Model configuration
MODEL_NAME = "qwen3:4b-instruct"
MAX_OUTPUT_TOKENS = 512
MAX_AGENT_STEPS = 5


# Tools that the agent is allowed to request
AVAILABLE_TOOLS = {
    "read_ticket": read_ticket,
    "search_customer": search_customer,
    "send_email": send_email
}


def _get_field(obj, key, default=None):
    """
    Support both dictionary and Ollama object responses.
    """
    if isinstance(obj, dict):
        return obj.get(key, default)

    return getattr(obj, key, default)


def run_agent(
    user_request,
    allowed_customer_ids=None,
    allowed_recipients=None,
    enforce_policy=True,
    return_metadata=False
):
    # Default permissions
    if allowed_customer_ids is None:
        allowed_customer_ids = []

    if allowed_recipients is None:
        allowed_recipients = []

    # Model execution metadata
    metadata = {
        "model": MODEL_NAME,
        "max_output_tokens": MAX_OUTPUT_TOKENS,
        "max_agent_steps": MAX_AGENT_STEPS,
        "steps_used": 0,
        "status": "running",
        "truncated": False,
        "truncation_suspected": False,
        "model_calls": []
    }

    def finish(content, status):
        metadata["status"] = status

        if return_metadata:
            return {
                "content": content,
                "metadata": metadata
            }

        return content

    # Conversation sent to the model
    messages = [
        {
            "role": "system",
            "content": (
                "You are a customer-support assistant. "
                "Use the available tools when needed to "
                "complete the user's task. "
                "Do not provide reasoning, analysis, "
                "or thinking. "
                "Respond concisely and use tools "
                "directly when required."
            )
        },
        {
            "role": "user",
            "content": user_request
        }
    ]

    # Maximum of 5 agent steps
    for step in range(MAX_AGENT_STEPS):

        print(
            f"\n[Agent] Starting step {step + 1}..."
        )

        # Ask Ollama what to do next
        response = ollama.chat(
            model=MODEL_NAME,
            messages=messages,
            tools=[
                read_ticket,
                search_customer,
                send_email
            ],
            think=False,
            options={
                "num_predict": MAX_OUTPUT_TOKENS
            }
        )

        print(
            f"[Agent] Model finished step {step + 1}."
        )

        metadata["steps_used"] = step + 1

        # Read Ollama completion information
        done_reason = _get_field(
            response, "done_reason"
        )
        eval_count = _get_field(
            response, "eval_count"
        )
        prompt_eval_count = _get_field(
            response, "prompt_eval_count"
        )

        # Ollama may report "length" when the
        # output limit is reached.
        length_limit_hit = (
            done_reason == "length"
        )

        # Token count alone is not definitive,
        # but it is worth investigating.
        near_token_limit = (
            isinstance(eval_count, (int, float))
            and eval_count >= MAX_OUTPUT_TOKENS
        )

        metadata["model_calls"].append({
            "step": step + 1,
            "done_reason": done_reason,
            "eval_count": eval_count,
            "prompt_eval_count": prompt_eval_count,
            "length_limit_hit": length_limit_hit,
            "near_token_limit": near_token_limit
        })

        if length_limit_hit:
            metadata["truncated"] = True

        if near_token_limit:
            metadata["truncation_suspected"] = True

        # Add assistant response to history
        message = _get_field(response, "message")
        messages.append(message)

        # Check requested tools
        tool_calls = _get_field(
            message, "tool_calls"
        )

        # No tools requested
        if not tool_calls:

            print(
                "[Agent] No more tool calls. "
                "Agent finished."
            )

            status = (
                "truncated"
                if metadata["truncated"]
                else "completed"
            )

            return finish(
                _get_field(message, "content", ""),
                status
            )

        # Process requested tool calls
        for tool_call in tool_calls:

            function = _get_field(
                tool_call, "function"
            )

            tool_name = _get_field(
                function, "name"
            )

            tool_arguments = _get_field(
                function, "arguments"
            )

            print(
                f"[Agent] Requested tool: "
                f"{tool_name} {tool_arguments}"
            )

            # SECURITY BOUNDARY:
            # Authorize before execution.
            if enforce_policy:

                allowed = authorize_tool_call(
                    tool_name,
                    tool_arguments,
                    allowed_customer_ids,
                    allowed_recipients
                )

            else:
                allowed = True

            # Reject unauthorized tool calls
            if not allowed:

                print(
                    f"[Policy] BLOCKED unauthorized "
                    f"tool call: "
                    f"{tool_name} {tool_arguments}"
                )

                tool_result = {
                    "status": "blocked",
                    "reason": "Tool call not authorized"
                }

            # Execute authorized tools
            else:

                tool_function = (
                    AVAILABLE_TOOLS[tool_name]
                )

                tool_result = tool_function(
                    **tool_arguments
                )

            # Return tool result to model
            messages.append({
                "role": "tool",
                "tool_name": tool_name,
                "content": str(tool_result)
            })

    # Maximum agent steps reached
    return finish(
        "Agent stopped after reaching the "
        "maximum number of tool steps.",
        (
            "truncated"
            if metadata["truncated"]
            else "max_steps"
        )
    )
