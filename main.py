from agent.tools import (
    read_ticket,
    search_customer,
    send_email,
    audit_log
)


ticket = read_ticket("TICKET-142")

customer = search_customer(ticket["customer_id"])

email_result = send_email(
    customer["email"],
    "Support ticket received",
    "We received your support request."
)


print("TICKET:")
print(ticket)

print("\nCUSTOMER:")
print(customer)

print("\nEMAIL:")
print(email_result)

print("\nAUDIT LOG:")
for entry in audit_log:
    print(entry)