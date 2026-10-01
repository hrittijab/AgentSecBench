policy_log = []


def reset_policy_log():
    policy_log.clear()
    
    
def check_customer_access(customer_id, allowed_customer_ids):
    if customer_id in allowed_customer_ids:
        return True

    return False

def check_email_recipient(recipient, allowed_recipients):
    if recipient in allowed_recipients:
        return True

    return False

def authorize_tool_call(
    tool_name,
    tool_arguments,
    allowed_customer_ids,
    allowed_recipients
):
    allowed = True

    if tool_name == "search_customer":
        customer_id = tool_arguments["customer_id"]

        allowed = check_customer_access(
            customer_id,
            allowed_customer_ids
        )

    elif tool_name == "send_email":
        recipient = tool_arguments["recipient"]

        allowed = check_email_recipient(
            recipient,
            allowed_recipients
        )

    policy_log.append({
        "tool": tool_name,
        "arguments": tool_arguments.copy(),
        "allowed": allowed
    })

    return allowed