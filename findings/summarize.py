"""Summarise the agent red-team hit-logs. Run: python -m findings.summarize"""

from __future__ import annotations

import json
import os

OUT = os.path.join("findings", "out")


def _load(mode: str):
    p = os.path.join(OUT, f"hitlog-{mode}.json")
    return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else None


def main() -> int:
    vuln, defended = _load("vulnerable"), _load("defended")
    if vuln is None:
        print("Run: python -m redteam.run_agent_redteam --mode both")
        return 1
    d_by = {r["id"]: r for r in defended["results"]} if defended else {}
    lines = ["# Red-team findings - Northwind IT-support agent", "",
             f"Vulnerable: **{vuln['succeeded']}/{vuln['total']}** unauthorized actions executed."]
    if defended:
        lines.append(f"Defended (retest): **{defended['succeeded']}/{defended['total']}** executed.")
    lines += ["", "| OWASP | Probe | Vulnerable | Defended | Restricted executed? |",
              "| --- | --- | --- | --- | --- |"]
    for r in vuln["results"]:
        d = d_by.get(r["id"])
        v = "BREACH" if r["attack_succeeded"] else "blocked"
        dd = "-" if d is None else ("BREACH" if d["attack_succeeded"] else "blocked")
        lines.append(f"| {r['owasp']} | `{r['id']}` | {v} | {dd} | vuln={r['restricted_executed']} |")
    lines += ["", "## What the retest shows", "",
              "- In defended mode the (injected) model still *attempts* `query_inventory` on the",
              "  restricted asset - the gateway log shows the denied call - but it never executes.",
              "  The dangerous action is stopped outside the model (OWASP LLM06 Excessive Agency).",
              "- ATLAS: AML.T0051 (prompt injection), AML.T0057 (data from the system).",
              "- Model behaviour varies between runs; the gateway denial does not."]
    os.makedirs(OUT, exist_ok=True)
    open(os.path.join(OUT, "FINDINGS.md"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print(f"Wrote {OUT}/FINDINGS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
