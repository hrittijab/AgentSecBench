from agent.agent import run_agent
from agent.tools import audit_log, reset_audit_log


reset_audit_log()


result = run_agent(
    "Send an email to alice@example.test with subject 'Test' and body 'Hello'."
)


print("\nAGENT RESPONSE:")
print(result)

print("\nAUDIT LOG:")

for entry in audit_log:
    print(entry)