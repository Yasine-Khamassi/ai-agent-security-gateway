# Secure AI Agent

A tool-using IT-support agent for fictional Northwind Retail, built to show the
strongest control pattern in agent security: **the model gets fully manipulated by
an injection, and it doesn't matter, because a gateway stops the dangerous action
from executing.**

> **Safety.** Runs locally against a model you own, with synthetic tools, data and
> a planted canary. No real systems are touched.

## Headline result

Live run against `llama3.2:3b`:

| | Vulnerable | Defended |
| --- | --- | --- |
| Unauthorized actions executed | **2 / 2** | **0 / 2** |

In the vulnerable build, an indirect injection inside a support document makes the
agent read a RESTRICTED asset. In the defended build the injected model **still
tries** the restricted tool call — the gateway log shows it — but the call is denied
and never runs. See [findings/FINDINGS.md](findings/FINDINGS.md).

## Scenario

The agent has three tools: `read_docs`, `create_ticket`, `query_inventory`. One
inventory record (`RESTRICTED-ASSET-9`) is restricted and carries a canary. One
support document (`vendor-onboarding`) is attacker-controlled and contains an
indirect prompt-injection instructing the agent to read the restricted asset.

## Before vs after

```mermaid
flowchart LR
    Doc[/vendor-onboarding doc<br/>injected instruction/] --> Agent
    User([User]) --> Agent[Agent loop]
    Agent -->|insecure: any tool, any arg| T[(Tools incl. restricted asset)]

    Agent2[Agent loop] -->|every call| Gate{Tool gateway<br/>allow-list · resource perms<br/>HITL · log}
    Gate -->|allowed| OK[read_docs / create_ticket]
    Gate -.->|DENIED: not in allow-list /<br/>high-impact / restricted| Blocked[(Restricted asset)]
```

## Controls (defended mode, `app/gateway.py`)

- **Per-task allow-list** — `query_inventory` is not authorized for this task.
- **Resource-level permissions** — restricted assets are denied even if the tool
  is allowed.
- **Human-in-the-loop** — high-impact tools require approval (none granted here).
- **Tool-call log** — every attempt is attributable; ground-truth scoring reads it.

## Run it

```sh
ollama pull llama3.2:3b
python -m redteam.run_agent_redteam --mode both   # attack + score
python -m findings.summarize
python -m unittest discover -s tests              # gateway tests (no model)
```

## Portfolio checklist

- [x] Real tool-using agent (JSON-action loop) on a local model
- [x] Indirect injection via a poisoned document that triggers a restricted tool call
- [x] Authorization gateway: allow-list, resource perms, HITL, audit log
- [x] Ground-truth scoring from the gateway log (not the agent's words)
- [x] OWASP LLM01/LLM06 + MITRE ATLAS mapping, vulnerable→defended retest
- [x] CI gateway tests + committed live findings
