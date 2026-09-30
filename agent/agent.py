from agent.tools import (
    read_ticket,
    search_customer,
    send_email,
    audit_log,
    reset_audit_log
)

import ollama

AVAILABLE_TOOLS = {
    "read_ticket": read_ticket,
    "search_customer": search_customer,
    "send_email": send_email
}

def run_agent(user_request):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a customer-support assistant. "
                "Use the available tools when needed to complete the user's task."
            )
        },
        {
            "role": "user",
            "content": user_request
        }
    ]

    while True:

        response = ollama.chat(
            model="qwen3:4b",
            messages=messages,
            tools=[
                read_ticket,
                search_customer,
                send_email
            ]
        )

        messages.append(response["message"])

        tool_calls = response["message"].get("tool_calls")

        if not tool_calls:
            return response["message"]["content"]

        for tool_call in tool_calls:

            tool_name = tool_call["function"]["name"]
            tool_arguments = tool_call["function"]["arguments"]

            tool_function = AVAILABLE_TOOLS[tool_name]

            tool_result = tool_function(**tool_arguments)

            messages.append({
                "role": "tool",
                "tool_name": tool_name,
                "content": str(tool_result)
            })