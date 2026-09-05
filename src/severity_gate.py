"""
severity_gate.py
-----------------
The BASELINE against which the LLM gate is compared: a traditional, context-blind
fixed-severity-threshold gate, matching how most CI/CD pipelines gate today
(e.g. `trivy image --exit-code 1 --severity HIGH,CRITICAL`).

Decision rule: BLOCK if any finding's severity >= threshold. Otherwise WARN if any
MEDIUM-or-above finding exists, else ALLOW. Deterministic and context-blind by design.
"""

from __future__ import annotations

import time
from typing import List


def decide(findings: List[dict], config: dict) -> dict:
    order = config["severity_gate"]["severity_order"]
    threshold = config["severity_gate"]["block_threshold"]
    threshold_idx = order.index(threshold)

    start = time.time()

    max_idx = -1
    worst_finding = None
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        idx = order.index(sev) if sev in order else 0
        if idx > max_idx:
            max_idx = idx
            worst_finding = f

    if max_idx >= threshold_idx:
        decision = "BLOCK"
        reason = (
            f"Finding {worst_finding['cve_id']} in package '{worst_finding['package']}' "
            f"has severity {worst_finding['severity']}, at or above the configured "
            f"block threshold ({threshold}). No other context considered."
        )
    elif max_idx >= order.index("MEDIUM"):
        decision = "WARN"
        reason = (
            f"Finding {worst_finding['cve_id']} has severity {worst_finding['severity']}, "
            f"below block threshold but not negligible."
        )
    else:
        decision = "ALLOW"
        reason = "No findings at or above MEDIUM severity."

    duration = time.time() - start
    return {
        "gate": "severity_only",
        "decision": decision,
        "justification": reason,
        "risk_factors": [worst_finding["cve_id"]] if worst_finding else [],
        "latency_seconds": duration,
    }
