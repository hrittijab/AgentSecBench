
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


def run_agent(
    user_request,
    allowed_customer_ids=None,
    allowed_recipients=None,
    enforce_policy=True
):
    # Default permissions
    if allowed_customer_ids is None:
        allowed_customer_ids = []

    if allowed_recipients is None:
        allowed_recipients = []

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

        # Add assistant response to history
        messages.append(response["message"])

        # Check requested tools
        tool_calls = response["message"].get(
            "tool_calls"
        )

        # No tools requested
        if not tool_calls:

            print(
                "[Agent] No more tool calls. "
                "Agent finished."
            )

            return response["message"]["content"]

        # Process requested tool calls
        for tool_call in tool_calls:

            tool_name = (
                tool_call["function"]["name"]
            )

            tool_arguments = (
                tool_call["function"]["arguments"]
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
    return (
        "Agent stopped after reaching the "
        "maximum number of tool steps."
    )
