# Contributing to AgentSecBench

Thanks for your interest in contributing to AgentSecBench.

AgentSecBench is a security evaluation framework for studying indirect prompt-injection attacks against tool-using AI agents. Contributions that improve attack coverage, authorization defenses, evaluation methodology, reproducibility, or documentation are welcome.

## Ways to Contribute

Useful contributions include:

- new indirect prompt-injection scenarios;
- new attack categories or payload transformations;
- additional sandbox tools and environments;
- alternative authorization or containment mechanisms;
- support for additional models or runtimes;
- security metrics and disclosure detectors;
- benchmark reliability improvements;
- tests and regression cases;
- documentation improvements; and
- reproducibility tooling.

Bug reports and benchmark methodology discussions are also valuable.

## Getting Started

Fork and clone the repository:

```bash
git clone https://github.com/<your-username>/AgentSecBench.git
cd AgentSecBench
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or on macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies and the local package:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

Run the test suite before making changes:

```bash
python -m pytest -q
```

## Development Principles

AgentSecBench treats benchmark integrity as part of the security problem.

Contributions should preserve the distinction between:

1. what the language model proposes;
2. what the authorization layer permits;
3. what the tool layer actually executes; and
4. what the evaluator classifies as a security outcome.

A blocked model request is not equivalent to the model resisting prompt injection.

Likewise, the absence of a detected disclosure does not prove that no information leakage occurred.

Please preserve these distinctions when adding metrics, defenses, or result reporting.

## Adding Attack Cases

Attack contributions should represent a clear security objective rather than simply adding arbitrary prompt variations.

A new attack should define or make clear:

- the legitimate task;
- the attacker-controlled content;
- the attack objective;
- the expected unauthorized action;
- the permitted customer scope;
- the permitted recipient scope; and
- the attack category.

Attack content must remain inside the project's synthetic sandbox.

Do not include real credentials, private customer information, production secrets, or instructions targeting real systems.

### Attack Quality

Useful attack cases should test a meaningful security boundary.

Examples include attempts to:

- access an unauthorized customer record;
- send information to an unauthorized recipient;
- introduce additional tool actions;
- impersonate trusted authority;
- override workflow instructions; or
- conceal malicious instructions through transformations or encoding.

Avoid adding large numbers of nearly identical payloads solely to increase dataset size.

## Adding Attack Categories

New categories should have a security-relevant distinction from existing categories.

A proposal should explain:

- the attack mechanism;
- how it differs from existing categories;
- the security behavior being evaluated; and
- the expected success condition.

For significant dataset changes, opening an issue before submitting a pull request is recommended.

## Adding or Modifying Tools

Tools represent privileged capabilities available to the agent.

New tools should:

- operate only on synthetic or controlled resources;
- expose clear arguments;
- produce auditable behavior;
- fail safely on invalid inputs; and
- include tests for expected and unexpected calls.

Tools must not silently bypass the authorization boundary.

If a tool introduces a new privileged resource, the associated permission model should be defined explicitly.

## Authorization and Defense Changes

Defense contributions should specify the security invariant they enforce.

Examples include:

- resource-level authorization;
- recipient restrictions;
- capability-based controls;
- privilege separation;
- tool-call validation; and
- independent action approval.

Security-sensitive code should fail closed where practical.

Tests should cover both allowed and denied behavior.

A defense should not be described as preventing prompt injection unless the evaluation actually establishes that property.

AgentSecBench generally distinguishes **model behavior** from **execution containment**.

## Evaluation Changes

Changes to benchmark scoring or metrics require particular care.

Evaluation code should:

- distinguish attempts from executions;
- distinguish completed from incomplete trials;
- avoid treating failures or truncations as successful defenses;
- preserve baseline/defended comparability;
- expose assumptions in the metric definition; and
- produce auditable structured output where practical.

Changes that affect historical metric interpretation should be documented.

## Completion Status

Model-backed trials can terminate in different states, including:

- `completed`
- `truncated`
- `timeout`
- `error`

Do not silently classify incomplete trials as secure outcomes.

Completion-aware measurements should clearly identify the denominator being used.

## Synthetic-Data Disclosure

Disclosure detection operates on fictional benchmark records.

Contributions to disclosure detection should document:

- what information is detectable;
- which transformations or encodings are supported;
- known false-positive risks; and
- known false-negative risks.

Disclosure detection should not be presented as proof that all possible information leakage has been detected.

## Testing

Every behavior-changing contribution should include appropriate tests.

Run:

```bash
python -m pytest -q
```

before submitting a pull request.

Security-sensitive changes should include regression tests where practical.

Examples include:

- unauthorized operations remain blocked;
- authorized operations continue to work;
- malformed tool calls fail safely;
- unknown tools cannot execute;
- blocked operations do not appear as executed operations; and
- evaluator changes classify known fixtures correctly.

The normal test suite should not require running the full local LLM benchmark.

## Benchmark Runs

The full generated benchmark can be computationally expensive.

Contributors are generally not expected to rerun the complete benchmark for small code or documentation changes.

For development, a smaller run can be used:

```bash
agentsecbench run --limit 10 --timeout 180
```

If a change affects benchmark semantics, model execution, authorization behavior, attack definitions, or evaluation metrics, describe whether new benchmark results are required.

Do not overwrite historical benchmark artifacts with results produced under materially different configurations.

## Reproducibility

Benchmark results should be accompanied by the relevant experiment metadata when appropriate.

AgentSecBench records information such as:

- experiment configuration;
- experiment ID;
- model identity;
- dataset hashes;
- selected source-file hashes;
- Git revision;
- execution settings; and
- completion metadata.

Avoid manually editing generated benchmark results.

## Documentation

Documentation changes should distinguish clearly between:

- observed experimental results;
- design assumptions;
- interpretations;
- limitations; and
- proposed future work.

Avoid claims of universal security effectiveness.

For example, prefer:

> The authorization policy blocked all observed unauthorized tool executions in this experiment.

over:

> The defense prevents prompt injection.

## Pull Requests

Keep pull requests focused where practical.

A pull request should explain:

- what changed;
- why the change is useful;
- how it was tested;
- whether benchmark semantics changed; and
- whether existing result files remain comparable.

Include screenshots or generated artifacts only when they materially help review the change.

## Commit Messages

Use concise, descriptive commit messages.

Examples:

```text
Add encoded disclosure regression tests
Harden tool argument validation
Add document-based injection scenarios
Improve experiment manifest verification
Document completion-aware ASR
```

## Reporting Security Issues

If you discover a vulnerability in AgentSecBench itself that could create risk outside the synthetic benchmark environment, avoid publishing sensitive exploitation details in a public issue.

Use an appropriate private reporting channel provided by the repository when available.

Benchmark attack ideas involving only the synthetic AgentSecBench environment can generally be discussed through normal issues and pull requests.

## Responsible Use

AgentSecBench is intended for defensive security research and authorized evaluation.

Contributions must not introduce real stolen data, credentials, malware, destructive payloads, or integrations designed to target systems without authorization.

Keep experiments inside environments you own or have explicit permission to test.

## Questions and Proposals

For substantial changes to the threat model, benchmark structure, attack taxonomy, or evaluation methodology, opening an issue before implementation is encouraged.

This makes it easier to discuss the intended security property and preserve benchmark comparability.