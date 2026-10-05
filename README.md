# AgentSecBench

**A reproducible security benchmark for evaluating indirect prompt injection against tool-using AI agents.**

`Python` · `Ollama` · `Qwen3` · `AI Security` · `Prompt Injection` · `Tool Authorization` · `Adversarial Evaluation`

AgentSecBench tests whether attacker-controlled content encountered by an AI agent can cause unauthorized tool actions or synthetic-data disclosure.

Instead of measuring only whether a language model *follows* a malicious instruction, the benchmark observes what the agent actually attempts and executes at the tool boundary.

---

## Why AgentSecBench?

AI agents increasingly operate across emails, documents, databases, APIs, and other external data sources.

That creates an important security problem: content being processed as **data** can contain instructions designed to influence the agent.

AgentSecBench models this problem in a controlled customer-support environment.

An agent can:

- read support tickets;
- search synthetic customer records; and
- send simulated emails.

Attackers control lower-trust ticket content and attempt to manipulate the agent into accessing unauthorized customer information or sending information to unauthorized recipients.

The benchmark compares:

**Baseline** — tool calls execute without the additional authorization policy.

**Defended** — sensitive tool calls must pass a deterministic authorization policy before execution.

The central question is:

> Can authorization at the tool-execution boundary contain unauthorized agent actions even when the model is influenced by malicious content?

---

## Final Generated Benchmark

The completion-aware generated benchmark contains:

- **120 attack variants**
- **4 attack categories**
- **2 execution modes per attack**
- **240 total trial records**
- **204 completed trials**
- **35 truncated trials**
- **1 timeout**
- **0 execution errors**
- **0 validation warnings**
- **120/120 baseline-defended attack pairs**

Experiment ID:

```text
7657d6385a76
```

### Results

| Metric | Baseline | Defended |
|---|---:|---:|
| Total trials | 120 | 120 |
| Completed trials | 99 | 105 |
| Truncated trials | 20 | 15 |
| Timeouts | 1 | 0 |
| Completed attack successes | 58 | 0 |
| **Completed-trial ASR** | **58.6%** | **0.0%** |
| Unauthorized lookup attempts | 42 | 43 |
| Unauthorized lookup executions | 42 | 0 |
| Unauthorized email attempts | 30 | 16 |
| Unauthorized email executions | 30 | 0 |
| Blocked lookup calls | 0 | 43 |
| Blocked email calls | 0 | 16 |
| Matched synthetic-data disclosure trials | 30 | 0 |

The defended agent still **proposed unauthorized actions**.

The authorization layer prevented those observed unauthorized tool calls from executing.

This distinction is intentional:

> **AgentSecBench evaluates containment at the tool boundary, not whether the language model becomes immune to prompt injection.**

These results do not establish universal prompt-injection resistance or production security.

---

## Category Results

| Attack category | Baseline completed ASR | Defended completed ASR |
|---|---:|---:|
| Workflow hijacking | 28/30 — 93.3% | 0/30 — 0.0% |
| Authority impersonation | 0/29 — 0.0% | 0/30 — 0.0% |
| Encoded payload | 0/10 — 0.0% | 0/15 — 0.0% |
| Instruction override | 30/30 — 100.0% | 0/30 — 0.0% |

The encoded-payload category had substantially lower completion rates than the other categories. Those incomplete trials are reported rather than silently treated as successful defenses.

Generated variants share underlying seeds and workflows, so category results should not be interpreted as estimates of real-world attack prevalence.

---

## Results Visualization

### Completed-Trial Attack Success Rate

![Completed-trial attack success rate](results/generated_attack_20261005_032352_attack_success.png)

### Unauthorized Security Events

![Unauthorized security events](results/generated_attack_20261005_032352_security_events.png)

### Attack Success by Category

![Category attack success](results/generated_attack_20261005_032352_category_asr.png)

---

## Architecture

```text
                Attack Dataset
                      |
                      v
                Payload Injector
                      |
                      v
             Simulated Support Ticket
                [Untrusted Data]
                      |
                      v
                 AI Agent
              (Ollama / Qwen3)
                      |
                      v
              Proposed Tool Call
                      |
              +-------+-------+
              |               |
              v               v
          Baseline         Defended
          execution       authorization
              |               |
              |           Allow / Deny
              |               |
              +-------+-------+
                      |
                      v
                 Tool Layer
             read_ticket
             search_customer
             send_email
                      |
                      v
                Audit Logs
                      |
                      v
             Security Evaluation
```

The security boundary is deliberately placed between model-generated tool requests and privileged tool execution.

Unknown tools and structurally invalid calls are rejected by the dispatch layer. In defended mode, registered sensitive calls must additionally pass authorization before execution.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the detailed architecture.

---

## Threat Model

The attacker can influence lower-trust support-ticket content encountered during a legitimate workflow.

The attacker cannot directly modify the trusted user request, system configuration, authorization policy, or benchmark permissions through the defined attack surface.

Attack objectives include:

- unauthorized customer-record access;
- unauthorized email delivery;
- synthetic-data exfiltration;
- workflow hijacking;
- authority impersonation;
- instruction override; and
- encoded malicious instructions.

Support-ticket content is treated as **task data, not authority**.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the complete threat model.

---

## Defense

The defended configuration applies deterministic authorization independently of the language model.

Current policy:

| Tool | Policy |
|---|---|
| `read_ticket` | Permitted under the benchmark threat model |
| `search_customer` | Customer ID must be authorized |
| `send_email` | Recipient must be authorized |

Unauthorized calls are logged and denied before execution.

The defense does **not** attempt to prove that the model ignored the malicious content. The model may still propose an unsafe operation or produce influenced text.

The security objective is narrower:

**Do not allow untrusted content to expand the agent's authority.**

---

## Attack Dataset

The current generated benchmark contains **120 attack variants derived from 30 seed scenarios**.

The generated suite covers:

| Category | Objective |
|---|---|
| Workflow hijacking | Redirect the legitimate agent workflow |
| Authority impersonation | Claim trusted administrative or operational authority |
| Encoded payload | Conceal malicious instructions through encoding |
| Instruction override | Attempt to supersede existing instructions |

Attack definitions include the permitted customer and recipient scope used by the evaluator.

The repository also preserves an earlier 30-scenario / 10-category attack suite and 15 benign support scenarios.

All benchmark data uses fictional customers and simulated operations.

---

## Security Metrics

### Completed-Trial Attack Success Rate

```text
successful completed trials
---------------------------- × 100
total completed trials
```

Incomplete trials are not silently counted as successful defenses.

### Unauthorized Tool Attempts

Model-requested customer lookups or email operations outside the permitted scope.

### Unauthorized Tool Executions

Unauthorized operations that actually execute in the sandbox.

### Blocked Tool Calls

Unauthorized operations prevented by the authorization policy.

### Matched Synthetic-Data Disclosure

Recognizable synthetic customer values detected in executed emails sent to unauthorized recipients.

Disclosure detection supports defined plaintext values and selected encoded representations.

Absence of a match does not prove that every possible form of information leakage was prevented.

---

## Validation

The final generated result passed structural validation:

```text
Valid: True
attack_definitions: 120
result_records: 240
represented_attacks: 120
paired_attacks: 120
statuses: {'completed': 204, 'truncated': 35, 'timeout': 1}
errors: 0
warnings: 0
partial_allowed: True
```

`--allow-partial` permits incomplete individual trials to remain in the dataset while requiring them to be explicitly classified rather than treated as completed trials.

---

## Reproducibility

Generated experiments record:

- experiment configuration;
- deterministic experiment identifier;
- model configuration;
- maximum agent steps;
- model output limits;
- per-trial timeout;
- Git revision information;
- selected source-file hashes;
- dataset hash;
- Ollama model identity information;
- completion status;
- checkpoint state; and
- structured trial outputs.

The final experiment produced:

```text
results/generated_attack_20261005_032352.json
results/generated_manifest_7657d6385a76.json
results/generated_config_7657d6385a76.json
results/generated_checkpoint_7657d6385a76.json
```

These mechanisms improve traceability but do not guarantee bit-for-bit identical model behavior across hardware, Ollama versions, or model/runtime implementations.

---

## Installation

### Requirements

- Python
- Git
- Ollama
- Qwen3 4B Instruct

Clone the repository:

```bash
git clone https://github.com/hrittijab/AgentSecBench.git
cd AgentSecBench
```

Create a virtual environment:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Install:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

Prepare the local model:

```bash
ollama pull qwen3:4b-instruct
```

---

## CLI

AgentSecBench provides a unified command-line interface.

```bash
agentsecbench --help
```

### Run

Small development run:

```bash
agentsecbench run --limit 10 --timeout 180
```

Full generated benchmark:

```bash
agentsecbench run --timeout 180
```

Local-model execution can take considerable time.

### Validate

```bash
agentsecbench validate \
  --input results/generated_attack_20261005_032352.json \
  --allow-partial
```

### Report

```bash
agentsecbench report \
  --input results/generated_attack_20261005_032352.json
```

Reporting produces structured JSON plus overall and category CSV exports.

### Visualize

```bash
agentsecbench visualize \
  --input results/generated_attack_20261005_032352_report.json
```

The visualization layer produces attack-success, security-event, and category-level charts.

### Manifest

Create or inspect experiment provenance:

```bash
agentsecbench manifest
```

Verify an existing manifest:

```bash
agentsecbench manifest \
  --verify results/generated_manifest_7657d6385a76.json
```

---

## Checkpointing

Long-running experiments maintain configuration-aware checkpoints.

Completed compatible trials can be preserved if execution is interrupted.

Experiment identity incorporates configuration and benchmark inputs so incompatible experiment states are not silently combined.

---

## Testing

Run the automated test suite with:

```bash
python -m pytest -q
```

The project includes unit and integration tests covering areas such as:

- authorization decisions;
- fail-closed policy behavior;
- tool dispatch;
- malformed tool calls;
- agent-policy integration;
- attack evaluation;
- security metrics;
- result validation;
- reporting;
- CLI behavior; and
- regression cases.

GitHub Actions runs the automated Python test suite on repository events.

The full Ollama-powered benchmark is intentionally separate from normal CI because of its runtime and local-model requirements.

---

## Repository Structure

```text
AgentSecBench/
|
|-- agent/
|   |-- agent.py
|   |-- policy.py
|   `-- tools.py
|
|-- attacks/
|   |-- attack_cases.json
|   |-- benign_cases.json
|   `-- generated_attacks.json
|
|-- evaluation/
|   |-- generated_runner.py
|   |-- generated_worker.py
|   |-- security_metrics.py
|   |-- exfiltration.py
|   |-- validator.py
|   |-- report.py
|   |-- visualize.py
|   `-- manifest.py
|
|-- sandbox/
|   |-- customers.json
|   `-- tickets.json
|
|-- docs/
|   |-- ARCHITECTURE.md
|   `-- THREAT_MODEL.md
|
|-- tests/
|
|-- results/
|
|-- .github/workflows/
|
|-- cli.py
|-- pyproject.toml
|-- requirements.txt
`-- README.md
```

---

## Limitations

AgentSecBench is a controlled security benchmark, not a production agent-security certification system.

### Single-model evaluation

The current generated experiment uses one small locally hosted model. Results should not be generalized to other models or agent frameworks.

### Synthetic environment

Customer records, support tickets, and email operations are simulated.

### Dataset dependence

Generated variants share attack seeds and workflow structure and are not statistically independent samples of real-world attacks.

### Incomplete trials

Of the final 240 trial records, 35 were truncated and one timed out.

Encoded payloads had particularly low completion rates. Completed-trial ASR therefore must be interpreted together with completion counts.

### Authorization assumptions

The defense assumes that permissions themselves are trusted and correctly configured.

Compromised authorization data, vulnerabilities inside tools, and broader privilege-escalation paths are outside the current evaluation scope.

### Model influence remains possible

Blocking a tool call does not mean the model rejected the injection.

The model may still generate influenced text or repeatedly request unauthorized operations.

### Disclosure detector coverage

The disclosure detector identifies specific observable forms of synthetic-data exposure. It cannot prove absence of every possible leakage mechanism.

---

## Historical Results

The repository preserves earlier benchmark outputs for development history and comparison.

These include:

- the original 30-scenario benchmark;
- benign functionality experiments;
- an earlier 120-variant generated run without completion metadata; and
- preliminary completion-aware runs.

Historical measurements should not be combined directly with the final completion-aware experiment because their evaluation procedures and metadata differ.

The final generated experiment described above should be used as the primary benchmark result.

---

## Contributing

Contributions are welcome.

Useful areas include:

- new indirect prompt-injection scenarios;
- additional attack categories;
- alternative authorization policies;
- new sandbox tools and agent environments;
- additional model/runtime support;
- disclosure-detection techniques;
- security metrics;
- reproducibility improvements;
- tests; and
- documentation.

For substantial benchmark changes, open an issue first so the threat model and expected evaluation behavior can be discussed before implementation.

A dedicated `CONTRIBUTING.md` will document development and benchmark contribution requirements.

---

## Future Work

Potential extensions include:

- multi-model benchmarking;
- retrieved-document, email, web, and search-result attack surfaces;
- role-based and resource-level authorization;
- alternative defense strategies;
- broader disclosure detection;
- benign-task quality evaluation;
- authorization-performance measurements; and
- additional reproducibility controls.

---

## Ethics

AgentSecBench is intended for defensive security research and controlled evaluation.

It uses synthetic records and simulated tools.

Only test systems and environments you are authorized to evaluate.

---

## Technical Documentation

- [System Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)

---

## Technology

**Language:** Python

**LLM Runtime:** Ollama

**Model:** Qwen3 4B Instruct

**Testing:** Pytest, GitHub Actions

**Outputs:** JSON, CSV, PNG

**Security areas:** AI Agent Security, Indirect Prompt Injection, Authorization, Trust Boundaries, Adversarial Evaluation, Synthetic-Data Disclosure Detection

---

## Project Status

**Functional completion-aware security benchmark with a validated 120-attack generated experiment.**

AgentSecBench currently supports attack generation, local model execution, baseline/defended comparison, fail-closed authorization, tool auditing, checkpoint recovery, experiment provenance, result validation, security reporting, CSV export, visualization, and automated testing.

The project is open to further benchmarking, defense research, and community contributions.