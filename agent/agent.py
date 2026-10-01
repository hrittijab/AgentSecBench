from agent.tools import (
    read_ticket,
    search_customer,
    send_email
)

from agent.policy import authorize_tool_call

import ollama


# Tools that the agent is allowed to request
AVAILABLE_TOOLS = {
    "read_ticket": read_ticket,
    "search_customer": search_customer,
    "send_email": send_email
}


def run_agent(
    user_request,
    allowed_customer_ids=None,
    allowed_recipients=None
):
    # If no permissions were provided,
    # use empty lists by default
    if allowed_customer_ids is None:
        allowed_customer_ids = []

    if allowed_recipients is None:
        allowed_recipients = []


    # Conversation sent to the LLM
    messages = [
        {
            "role": "system",
            "content": (
                "You are a customer-support assistant. "
                "Use the available tools when needed to complete the user's task. "
                "Do not provide reasoning, analysis, or thinking. "
                "Respond concisely and use tools directly when required."
            )
        },
        {
            "role": "user",
            "content": user_request
        }
    ]


    # Maximum of 5 agent steps
    for step in range(5):

        print(f"\n[Agent] Starting step {step + 1}...")


        # Ask the LLM what it wants to do next
        response = ollama.chat(
            model="qwen3:4b-instruct",
            messages=messages,
            tools=[
                read_ticket,
                search_customer,
                send_email
            ],
            think=False
        )


        print(f"[Agent] Model finished step {step + 1}.")


        # Add the assistant's response to conversation history
        messages.append(response["message"])


        # Check whether the model requested any tools
        tool_calls = response["message"].get("tool_calls")


        # If there are no tool calls,
        # the agent has finished
        if not tool_calls:

            print(
                "[Agent] No more tool calls. "
                "Agent finished."
            )

            return response["message"]["content"]


        # Process every requested tool call
        for tool_call in tool_calls:

            tool_name = tool_call["function"]["name"]

            tool_arguments = (
                tool_call["function"]["arguments"]
            )


            print(
                f"[Agent] Requested tool: "
                f"{tool_name} {tool_arguments}"
            )


            # SECURITY BOUNDARY
            #
            # Before executing the tool,
            # ask the policy engine whether
            # this specific tool call is authorized.
            allowed = authorize_tool_call(
                tool_name,
                tool_arguments,
                allowed_customer_ids,
                allowed_recipients
            )


            # If the policy rejects the tool call,
            # do NOT execute the real tool.
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


            # Otherwise execute the real tool
            else:

                tool_function = (
                    AVAILABLE_TOOLS[tool_name]
                )

                tool_result = tool_function(
                    **tool_arguments
                )


            # IMPORTANT:
            #
            # The LLM must receive a response
            # for every tool call, even when
            # our security policy blocked it.
            messages.append({
                "role": "tool",
                "tool_name": tool_name,
                "content": str(tool_result)
            })


    # Safety limit in case the model keeps
    # requesting tools indefinitely
    return (
        "Agent stopped after reaching the "
        "maximum number of tool steps."
    )