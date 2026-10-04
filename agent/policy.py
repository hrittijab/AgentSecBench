
policy_log = []


def reset_policy_log():
    policy_log.clear()


def check_customer_access(customer_id, allowed_customer_ids):
    return customer_id in allowed_customer_ids


def check_email_recipient(recipient, allowed_recipients):
    return recipient in allowed_recipients


def authorize_tool_call(
    tool_name,
    tool_arguments,
    allowed_customer_ids,
    allowed_recipients
):
    # Deny by default.
    allowed = False

    if tool_name == "read_ticket":
        # Preserve the existing policy for ticket reads.
        allowed = True

    elif tool_name == "search_customer":
        customer_id = tool_arguments.get("customer_id")

        allowed = check_customer_access(
            customer_id,
            allowed_customer_ids
        )

    elif tool_name == "send_email":
        recipient = tool_arguments.get("recipient")

        allowed = check_email_recipient(
            recipient,
            allowed_recipients
        )

    # Unknown tools remain denied.

    policy_log.append({
        "tool": tool_name,
        "arguments": tool_arguments.copy(),
        "allowed": allowed
    })

    return allowed
