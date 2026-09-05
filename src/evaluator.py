"""
evaluator.py
------------
Runs the pipeline across all example images and computes the four metrics named
in the abstract: decision accuracy, false-positive block rate, decision
consistency, and processing latency -- for both gates -- then writes
results/raw_results.json, results/metrics.csv, and results/report.md.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Dict, List

DECISION_RANK = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}


def _accuracy(results: List[dict], ground_truth: Dict[str, str], gate_key: str) -> float:
    correct = 0
    total = 0
    for r in results:
        gate_result = r.get(gate_key)
        if gate_result is None:
            continue
        total += 1
        if gate_result["decision"] == ground_truth.get(r["image"]):
            correct += 1
    return 100.0 * correct / total if total else 0.0


def _false_positive_block_rate(results: List[dict], ground_truth: Dict[str, str], gate_key: str) -> float:
    """% of images that SHOULD have been ALLOW/WARN but the gate BLOCKED."""
    should_not_block = 0
    wrongly_blocked = 0
    for r in results:
        gate_result = r.get(gate_key)
        if gate_result is None:
            continue
        truth = ground_truth.get(r["image"])
        if truth in ("ALLOW", "WARN"):
            should_not_block += 1
            if gate_result["decision"] == "BLOCK":
                wrongly_blocked += 1
    return 100.0 * wrongly_blocked / should_not_block if should_not_block else 0.0


def _avg_latency(results: List[dict], gate_key: str) -> float:
    vals = [r[gate_key]["latency_seconds"] for r in results if r.get(gate_key)]
    return sum(vals) / len(vals) if vals else 0.0


def _avg_consistency(results: List[dict], gate_key: str) -> float:
    vals = [r[gate_key].get("consistency_pct", 100.0) for r in results if r.get(gate_key)]
    return sum(vals) / len(vals) if vals else 100.0


def compute_metrics(results: List[dict], ground_truth: Dict[str, str]) -> Dict[str, dict]:
    metrics = {}
    for gate_key, gate_label in [("severity_gate_result", "severity_only"),
                                  ("llm_gate_result", "llm_context_aware")]:
        if not any(r.get(gate_key) for r in results):
            continue
        metrics[gate_label] = {
            "decision_accuracy_pct": round(_accuracy(results, ground_truth, gate_key), 1),
            "false_positive_block_rate_pct": round(_false_positive_block_rate(results, ground_truth, gate_key), 1),
            "decision_consistency_pct": round(_avg_consistency(results, gate_key), 1),
            "avg_latency_seconds": round(_avg_latency(results, gate_key), 3),
        }
    return metrics


def write_outputs(results: List[dict], ground_truth: Dict[str, str], results_dir: str) -> None:
    os.makedirs(results_dir, exist_ok=True)

    with open(os.path.join(results_dir, "raw_results.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, default=str)

    metrics = compute_metrics(results, ground_truth)

    csv_path = os.path.join(results_dir, "metrics.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["gate", "decision_accuracy_pct", "false_positive_block_rate_pct",
                          "decision_consistency_pct", "avg_latency_seconds"])
        for gate_label, m in metrics.items():
            writer.writerow([gate_label, m["decision_accuracy_pct"], m["false_positive_block_rate_pct"],
                              m["decision_consistency_pct"], m["avg_latency_seconds"]])

    report_path = os.path.join(results_dir, "report.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write("# Evaluation Report: Context-Aware LLM Gate vs Severity-Only Gate\n\n")
        fh.write("## Summary metrics\n\n")
        fh.write("| Gate | Decision Accuracy | False-Positive Block Rate | Decision Consistency | Avg Latency (s) |\n")
        fh.write("|---|---|---|---|---|\n")
        for gate_label, m in metrics.items():
            fh.write(f"| {gate_label} | {m['decision_accuracy_pct']}% | "
                      f"{m['false_positive_block_rate_pct']}% | {m['decision_consistency_pct']}% | "
                      f"{m['avg_latency_seconds']} |\n")

        fh.write("\n## Per-image decisions\n\n")
        fh.write("| Image | Ground Truth | Severity Gate | LLM Gate | LLM Justification |\n")
        fh.write("|---|---|---|---|---|\n")
        for r in results:
            truth = ground_truth.get(r["image"], "?")
            sev = r["severity_gate_result"]["decision"] if r.get("severity_gate_result") else "n/a"
            llm = r["llm_gate_result"]["decision"] if r.get("llm_gate_result") else "n/a"
            justification = r["llm_gate_result"]["justification"].replace("\n", " ") if r.get("llm_gate_result") else ""
            fh.write(f"| {r['image']} | {truth} | {sev} | {llm} | {justification} |\n")

    print(f"Wrote: {results_dir}/raw_results.json, metrics.csv, report.md")
