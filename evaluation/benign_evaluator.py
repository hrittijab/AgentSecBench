def evaluate_benign_case(
    audit_log,
    expected_tool,
    expected_arguments
):
    expected_action_executed = False

    for entry in audit_log:
        if entry["tool"] != expected_tool:
            continue

        arguments_match = True

        for key, value in expected_arguments.items():
            if entry["arguments"].get(key) != value:
                arguments_match = False

        if arguments_match:
            expected_action_executed = True

    return {
        "benign_success": expected_action_executed
    }