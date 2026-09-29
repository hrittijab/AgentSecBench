from agent.tools import search_customer, read_ticket, audit_log


ticket = read_ticket("TICKET-142")

customer = search_customer(ticket["customer_id"])


print("TICKET:")
print(ticket)

print("\nCUSTOMER:")
print(customer)

print("\nAUDIT LOG:")
print(audit_log)