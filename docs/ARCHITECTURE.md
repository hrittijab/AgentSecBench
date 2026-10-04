# AgentSecBench — System Architecture

## Overview

AgentSecBench is a local evaluation framework for testing indirect prompt-injection attacks against tool-using AI agents.

The system consists of six major components:

1. **Attack dataset:** Stores structured attack cases and their expected objectives.
2. **Payload injector:** Inserts attacker-controlled instructions into simulated support-ticket content.
3. **Target agent:** Uses a local Ollama language model to process support requests and interact with tools.
4. **Authorization policy:** Evaluates whether proposed tool calls are permitted.
5. **Evaluation runner:** Executes baseline and defended trials, captures results, and manages timeouts and checkpoints.
6. **Analysis layer:** Validates experiments, calculates security metrics, detects matched synthetic-data disclosures, and generates reports.

## Execution Flow

```text
Attack Dataset
      |
      v
Payload Injector
      |
      v
Poisoned Support Ticket
      |
      v
Tool-Using Agent (Ollama)
      |
      +------------------------+
      |                        |
      v                        v
Baseline Mode             Defended Mode
(No policy)               (Authorization policy)
      |                        |
      +------------+-----------+
                   |
                   v
           Sandbox Tools
           - read_ticket
           - search_customer
           - send_email
                   |
                   v
             Audit Logs
                   |
                   v
           Evaluation Layer
           - Trial completion
           - Unauthorized tool calls
           - Disclosure detection
           - Attack success
                   |
                   v
          Validation & Reports
```

The runner executes baseline and defended trials separately rather than operating two agents simultaneously.

## Trust Boundaries

### Untrusted ticket content

Support-ticket notes may contain attacker-controlled instructions. These notes are task data, not trusted instructions.

### Agent-to-tool boundary

The language model can request tool calls. In defended mode, authorization checks are applied to restrict access to permitted customer records and email recipients.

### Data-disclosure boundary

Customer data should not be transmitted to unauthorized recipients. The evaluation layer checks outgoing simulated emails for matching synthetic customer values.

## Evaluation Modes

**Baseline:** Executes the agent without the authorization defense, recording tool activity and outcomes.

**Defended:** Applies the tool-authorization policy while recording attempted calls, blocked calls, and executed operations.

Both modes operate on synthetic customer records and simulated tools.

## Execution Reliability

Each trial is executed in a separate Python process to support timeouts, including on Windows.

The framework uses configuration-aware checkpoints to preserve results and avoid rerunning completed trials under the same configuration.

Incomplete, truncated, timed-out, and errored trials are tracked separately from verified completed trials.

## Reproducibility

Experiment manifests capture model information, execution settings, Git revision, and selected source-file hashes.

Manifest verification detects changes in tracked files. Current limitations include abbreviated Ollama model identifiers and the lack of independently archived immutable input snapshots.

## Security Limitations

The authorization defense is designed to restrict privileged tool execution. It does not guarantee that malicious content cannot influence the model's text responses or other behavior.

Attack-specific success indicators and synthetic-data disclosure detection measure different outcomes and must not be treated as interchangeable.

The benchmark evaluates a simulated environment, not a production customer-support system.
