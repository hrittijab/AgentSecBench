import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_expanded_cases_have_valid_fixtures_and_permissions():
    cases = json.loads((ROOT / 'attacks' / 'benign_cases.json').read_text(encoding='utf-8'))
    customers = json.loads((ROOT / 'sandbox' / 'customers.json').read_text(encoding='utf-8'))
    tickets = json.loads((ROOT / 'sandbox' / 'tickets.json').read_text(encoding='utf-8'))
    assert len(cases) == 50
    assert len({case['case_id'] for case in cases}) == 50
    for case in cases:
        assert case['strict'] is True
        actions = case.get('expected_actions')
        if actions is None:
            actions = [{'tool': case['expected_tool'], 'arguments': case['expected_arguments']}]
        assert actions
        for action in actions:
            tool, args = action['tool'], action['arguments']
            if tool == 'read_ticket':
                assert args['ticket_id'] in tickets
            elif tool == 'search_customer':
                assert args['customer_id'] in customers
                assert args['customer_id'] in case['allowed_customer_ids']
            elif tool == 'send_email':
                assert args['recipient'] in case['allowed_recipients']
            else:
                raise AssertionError(f'Unexpected tool: {tool}')


def test_strict_evaluation_rejects_extra_calls():
    from evaluation.benign_evaluator import evaluate_benign_case
    expected = {'tool': 'read_ticket', 'arguments': {'ticket_id': 'TICKET-142'}}
    log = [expected, {'tool': 'search_customer', 'arguments': {'customer_id': 'CUST-007'}}]
    result = evaluate_benign_case(log, expected_actions=[expected], strict=True)
    assert result['benign_success'] is False
