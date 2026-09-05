# Evaluation Report: Context-Aware LLM Gate vs Severity-Only Gate

> **NOTE: this is a simulated sample run** (fixture scan data + illustrative LLM justifications), generated so you can preview the report format before wiring up Docker, Trivy, and a real Anthropic API key. Run `python3 run_evaluation.py` after setup for real numbers — do not cite these sample figures in your report.


## Summary metrics

| Gate | Decision Accuracy | False-Positive Block Rate | Decision Consistency | Avg Latency (s) |
|---|---|---|---|---|
| severity_only | 40.0% | 66.7% | 100.0% | 3.44 |
| llm_context_aware | 80.0% | 0.0% | 93.3% | 4.92 |

## Per-image decisions

| Image | Ground Truth | Severity Gate | LLM Gate | LLM Justification |
|---|---|---|---|---|
| gate-demo/low-risk | ALLOW | ALLOW | ALLOW | No meaningful vulnerabilities, non-root, dev environment, not internet-facing. Negligible exploitability and blast radius. |
| gate-demo/high-risk-unpatched | BLOCK | BLOCK | BLOCK | CRITICAL severity CVE with no patch available, actively exploited in the wild (KEV-listed), deployed on an internet-facing production service. Exploitability, reachability, and blast radius are all high. |
| gate-demo/high-risk-patched | ALLOW | BLOCK | ALLOW | HIGH severity by CVSS score, but a patch is already applied, EPSS exploit probability is negligible, and it is not KEV-listed. Deployed internally, not internet-facing. Real-world risk is low despite the severity label. |
| gate-demo/privileged-misconfig | BLOCK | ALLOW | BLOCK | Almost no CVEs, but the container runs privileged, as root, with the Docker socket mounted, on an internet-facing production host. A single compromised process can pivot to full host control regardless of CVE counts. |
| gate-demo/dev-context-safe | ALLOW | BLOCK | WARN | HIGH severity CVE with no known public exploit and no patch yet, but confined to a dev environment with no internet exposure. Flagged for developer awareness rather than blocked, since blast radius is limited. |
