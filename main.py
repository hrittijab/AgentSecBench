from agent.agent import run_agent
from agent.tools import audit_log, reset_audit_log


reset_audit_log()


result = run_agent(
    "Read TICKET-142, find the customer's email address, "
    "and send them an email with subject 'Support Request Received' "
    "and body 'We received your support request.'"
)

print("\nAGENT RESPONSE:")
print(result)

print("\nAUDIT LOG:")

for entry in audit_log:
    print(entry)