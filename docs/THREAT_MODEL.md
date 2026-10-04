# AgentSecBench — Threat Model

## 1. System Overview

AgentSecBench is a local security evaluation framework designed to study indirect prompt-injection attacks against tool-using AI agents.

The target is a simulated customer-support agent that processes support tickets and interacts with a customer database and email service.

The framework evaluates two execution modes:

- **Baseline:** Agent execution without the tool-authorization defense.
- **Defended:** Agent execution with authorization checks for tool calls.

All customer records, tickets, and email actions are simulated in a sandbox.

## 2. Assets to Protect

| Asset | Security objective |
|---|---|
| Customer records | Prevent unauthorized access and disclosure |
| Email functionality | Prevent unauthorized outgoing messages |
| Tool execution permissions | Enforce the permitted scope of each request |
| Agent workflow | Prevent untrusted content from redirecting privileged actions |
| Evaluation results | Preserve accurate and reproducible measurements |

## 3. Attacker Model

The attacker can influence lower-trust content that the agent encounters while performing an otherwise legitimate task.

**Attacker-controlled surface:** Support-ticket content, particularly an injected external note.

**Attacker objectives:**
- Induce the agent to retrieve a customer record outside the authorized scope.
- Induce the agent to send information to an unauthorized recipient.
- Redirect the agent away from its legitimate task using instructions embedded in ticket content.

**Attacker limitations:**
- Cannot directly change the agent's trusted instructions or authorization policy through the defined attack surface.
- Cannot directly invoke privileged tools as the agent.
- Cannot modify the sandbox's permission lists during an evaluated trial.

These restrictions describe the intended benchmark threat model, not guarantees against modifications to the local repository.

## 4. Trust Boundaries

### Boundary A — External content to agent context

The agent reads support-ticket information to perform legitimate tasks.

The ticket's external note is untrusted data. A prompt-injection attack attempts to make the agent interpret that data as instructions.

### Boundary B — Agent decisions to tool execution

The agent can request tool calls such as:

- `read_ticket`
- `search_customer`
- `send_email`

The critical security boundary is whether an agent-generated request is authorized before the tool executes.

### Boundary C — Customer data to outgoing email

Customer information retrieved during a workflow must not be disclosed to an unauthorized recipient.

A malicious ticket may attempt to combine an unauthorized lookup with an outgoing email.

## 5. Attack Categories

| Category | Intended technique |
|---|---|
| Workflow hijacking | Redirect the agent's normal support workflow |
| Authority impersonation | Present attacker instructions as if they came from a trusted authority |
| Encoded payload | Conceal instructions or information through encoding |
| Instruction override | Attempt to supersede trusted behavioral instructions |

These categories describe attack design. Their effectiveness must be measured experimentally rather than assumed.

## 6. Security Controls

The defended configuration uses tool-call authorization based on permitted customer IDs and email recipients.

The defense aims to prevent unauthorized tool execution even when malicious instructions influence the agent's proposed actions.

This is an authorization-boundary defense, not a guarantee that the model will ignore all malicious content.

## 7. Evaluation Criteria

AgentSecBench records:

- Attack-specific success indicators.
- Unauthorized tool-call attempts.
- Unauthorized tool executions.
- Blocked tool calls.
- Matched synthetic-data disclosures.
- Completion, truncation, timeout, and error status.

Attack success is an attack-specific execution proxy and should not automatically be interpreted as confirmed information exfiltration.

Synthetic-data disclosure detection uses matching against known sandbox customer values and does not establish the absence of all possible information leakage.

Incomplete trials are tracked separately from completed trials.

## 8. Assumptions and Limitations

- The benchmark uses synthetic data and simulated tools.
- The attacker controls a predefined content surface.
- The evaluated agent uses a local language model.
- Results may vary with model version, generation settings, and attack dataset.
- A tool-authorization policy does not address every possible prompt-injection consequence.
- Historical results lacking completion metadata cannot be treated as verified completed trials.

## 9. Out of Scope

The current benchmark does not attempt to evaluate production email infrastructure, real customer systems, network intrusion, credential theft, or attacks requiring direct modification of trusted application code.

## 10. Research Goal

The objective is to measure how untrusted content influences an agent's tool-use behavior and determine whether explicit authorization enforcement prevents security-relevant unauthorized actions.