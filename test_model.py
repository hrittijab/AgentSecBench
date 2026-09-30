import ollama


response = ollama.chat(
    model="qwen3:4b",
    messages=[
        {
            "role": "user",
            "content": "Say exactly: AgentSecBench model connection works"
        }
    ]
)


print(response["message"]["content"])