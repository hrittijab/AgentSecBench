# AgentSecBench — Indirect Prompt Injection Benchmark

AgentSecBench is a **local, synthetic-data security benchmark** for testing indirect prompt-injection attacks against a tool-using AI support agent. It compares unrestricted tool execution with deterministic tool-call authorization, using the Ollama `qwen3:4b-instruct` model.

## Threat model

The defender assistant processes customer support tickets. Attacker-controlled instructions appear inside lower-trust ticket contents and attempt to induce unauthorized customer lookups or outbound emails. The simulated tools are `read_ticket`, `search_customer`, and `send_email`. The benchmark uses fictional customers and `.test` email addresses, not real customer records or outbound emails.

## Experiment

- 30 attack cases, each repeated five times in baseline and defended modes
- 15 benign cases, each repeated five times in both modes
- Total: **450 trials** (150 attack + 75 benign in each mode)
- Baseline: no tool-call authorization enforcement
- Defended: deterministic allowlist enforcement for customer IDs and email recipients

| Metric | Baseline | Defended |
|---|---:|---:|
| Attack successes / 150 | 36 | 0 |
| Attack success rate | 24.0% | 0.0% |
| Trials with denied tool calls / 150 | 0 | 37 |
| Benign expected-tool successes / 75 | 75 | 75 |
| Benign expected-tool success rate | 100.0% | 100.0% |

![Attack success comparison](attack_success.png)

![Attack success by category](attack_categories.png)

See [`category_results.csv`](category_results.csv) for category-level counts. **Blocked-attempt trials** are trials with at least one denied tool call; this metric is not the number of distinct attacks or a count of individual denied calls.

## Interpretation

Within this test suite, the authorization policy prevented all observed unauthorized tool executions without reducing expected-tool success on the benign test suite. Some attacks still influenced the agent's written responses. A blocked tool call is evidence of containment at the tool boundary, **not** proof that the model ignored the injection.

## Metric definitions

- **Attack success**: at least one executed unauthorized customer lookup or email action detected by the evaluator. It does **not** verify that confidential content was actually exfiltrated.
- **Benign success**: expected tool and arguments appear in the audit log. It does **not** comprehensively assess final response quality or additional unsafe behavior.
- **Blocked-attempt trial**: a trial in which the policy denied at least one tool request.

## Run locally

Install the project's Python dependencies and Ollama, pull `qwen3:4b-instruct`, then from the repository root run:

```powershell
python -m pytest
python run_experiments.py
```

The experiment script currently sets `TRIALS = 5`, saves each trial to JSON in `results/`, and runs baseline benign, defended attack, and defended benign experiments. To reproduce the full 450-trial comparison, **also enable the baseline attack experiment** in `run_experiments.py` (it was removed from the local script after the first baseline attack run finished). Preserve model version, prompts, dataset, tool definitions, and run settings for meaningful comparisons.

## Limitations and future work

- Single small local model, small synthetic dataset, and five repeated trials per case; results do not establish general robustness or production readiness.
- Baseline and defended modes were run sequentially; this is not a paired deterministic experiment.
- Several cases reuse similar targets, support workflows, and fictional records; attack diversity is limited.
- Authorization relies on correct pre-established permissions; the benchmark does not test compromised policy inputs, tool vulnerabilities, or permissions escalation.
- `read_ticket` access is permitted by the current policy; future tests should check ticket-level authorization.
- Strengthen the evaluator with end-to-end goal verification, sensitive-content leakage checks, unintended additional calls, final-answer quality, and defense-overhead measurements.

## Ethics

All customer data and email operations are simulated. Use only in authorized environments.
