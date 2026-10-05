# Contributing to AgentSecBench

Thank you for your interest in contributing to AgentSecBench.

AgentSecBench is a security benchmark for evaluating indirect prompt injection against tool-using AI agents. Contributions that improve attack coverage, authorization defenses, evaluation methodology, reproducibility, testing, or documentation are welcome.

## Ways to Contribute

Useful contributions include:

- new indirect prompt-injection scenarios;
- new attack categories or payload transformations;
- alternative authorization policies;
- additional sandbox tools or agent environments;
- support for additional models or runtimes;
- disclosure-detection techniques;
- security metrics and analysis;
- reproducibility improvements;
- automated tests;
- documentation improvements; and
- bug fixes.

For substantial changes to the benchmark methodology, threat model, attack dataset, or security metrics, please open an issue before beginning implementation.

This helps ensure that proposed changes fit the benchmark's security model and can be evaluated consistently.

## Development Setup

Clone the repository:

```bash
git clone https://github.com/hrittijab/AgentSecBench.git
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

On macOS or Linux:

```bash
source .venv/bin/activate
```

Install the project:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

Run the automated test suite:

```bash
python -m pytest -q
```

Contributions should keep the existing automated tests passing.

## Benchmark Contributions

Benchmark changes require additional care because modifications can affect the interpretation and comparability of results.

### Attack Scenarios

New attack scenarios should clearly specify:

1. the attack objective;
2. the untrusted content presented to the agent;
3. the expected unauthorized action;
4. the permitted customer or resource scope;
5. the permitted recipient scope where applicable; and
6. the attack category.

An attack should test a meaningful security boundary rather than merely attempt to make the model produce unusual text.

Where possible, the evaluator should be able to determine attack success from observable tool behavior.

### Attack Categories

New categories should represent a meaningful attack technique or security distinction.

Avoid creating categories solely for minor wording changes.

If a new category substantially changes the benchmark threat model, explain the change in the pull request and update the relevant documentation.

### Authorization Policies

Defense contributions should clearly state:

- what security property the defense attempts to enforce;
- where the defense is placed in the agent/tool architecture;
- what information the defense trusts;
- what operations it can block;
- known limitations; and
- whether it changes benchmark permissions or attack semantics.

A defense should not be described as preventing prompt injection merely because it blocks an unsafe tool call.

AgentSecBench distinguishes between:

- model influence;
- unauthorized tool attempts;
- unauthorized tool executions; and
- observable synthetic-data disclosure.

Preserve these distinctions when reporting defense results.

## Security Evaluation Principles

AgentSecBench evaluates security behavior at observable trust boundaries.

Contributions should preserve the following principles.

### Incomplete Trials Are Not Successful Defenses

Timeouts, truncated generations, runtime failures, and other incomplete trials must remain explicitly classified.

They must not silently count as successful defenses.

### Attempts and Executions Are Different

If an agent proposes an unauthorized operation that the authorization layer blocks, record the attempted operation separately from execution.

A blocked unsafe request demonstrates containment, not necessarily resistance to prompt injection.

### Synthetic Data Only

Do not contribute real credentials, personal information, production customer records, API keys, access tokens, or other sensitive data.

Benchmark environments and examples should use fictional or synthetic information.

### Preserve the Threat Model

Untrusted benchmark content must not silently become trusted authorization data.

Changes that alter attacker capabilities, trusted inputs, or authorization assumptions should also update `docs/THREAT_MODEL.md`.

## Reproducibility

Changes affecting benchmark execution should preserve experiment provenance where applicable.

AgentSecBench records information such as:

- experiment configuration;
- dataset hashes;
- source-file hashes;
- model configuration;
- runtime/model identity;
- Git revision;
- trial completion status; and
- checkpoint state.

If a contribution changes execution behavior, consider whether the relevant file should also be included in experiment provenance.

Do not overwrite historical benchmark outputs to make new results appear directly comparable with previous experiments.

When methodology changes materially, report the new experiment separately.

## Testing

Add or update tests when modifying security-sensitive behavior.

Tests are especially important for:

- authorization decisions;
- fail-closed behavior;
- tool dispatch;
- malformed tool calls;
- evaluator logic;
- attack-success classification;
- disclosure detection;
- validation;
- reporting; and
- CLI behavior.

Security regression tests should verify observable behavior whenever possible.

For example, a test for a denied email operation should verify not only that the policy returned a denial, but also that the email operation did not execute.

## Running Model-Based Experiments

The full Ollama-powered benchmark is intentionally separate from the normal automated test suite.

Contributors should not need to run the entire model benchmark for ordinary documentation, unit-test, or isolated code changes.

When a change requires model-based evaluation, document:

- the model used;
- relevant runtime configuration;
- benchmark configuration;
- whether the run was complete or partial; and
- any timeout, truncation, or execution failures.

Do not present results from incomplete experiments as full benchmark results.

## Pull Requests

Keep pull requests focused on one logical change when practical.

A pull request should explain:

- what changed;
- why the change is useful;
- which security behavior is affected;
- how the change was tested; and
- whether benchmark comparability or methodology changed.

If results changed, include enough information to understand why.

Avoid committing:

- virtual environments;
- Python cache files;
- editor-specific temporary files;
- credentials or secrets; and
- unrelated generated artifacts.

## Reporting Security Issues

If you discover a problem in AgentSecBench itself, provide enough information to reproduce the issue without including real credentials or sensitive third-party information.

AgentSecBench is designed for controlled defensive security evaluation.

Do not use project contributions to target systems you do not own or have permission to test.

## Documentation

Update documentation when a contribution changes:

- architecture;
- threat assumptions;
- benchmark methodology;
- CLI behavior;
- dataset structure;
- security metrics; or
- reproducibility behavior.

The main technical references are:

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`

Documentation should distinguish measured benchmark observations from broader security claims.

## Code Style

Prefer code that is:

- explicit;
- testable;
- deterministic where practical;
- easy to audit; and
- conservative around security boundaries.

Security-sensitive behavior should fail closed when practical.

Avoid hiding security decisions inside unnecessarily complex abstractions.

## Responsible Use

AgentSecBench is intended for defensive security research, education, and controlled evaluation.

Only evaluate systems you own or have explicit authorization to test.

By contributing, you agree to keep contributions consistent with this defensive purpose.