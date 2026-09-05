#!/usr/bin/env python3
"""
run_evaluation.py
------------------
Single entry point for the whole project. For every example image:
  1. Scans it with Trivy (or a fixture, with --offline)
  2. Enriches findings with exploit intel (live APIs, or deterministic overrides
     in examples/enrichment_overrides.json so the demo narrative is reproducible)
  3. Analyzes container configuration risk (static Dockerfile parsing, with
     runtime-flag overrides in examples/config_risk_overrides.json where needed)
  4. Loads deployment context from examples/deployment_context.json
  5. Runs BOTH the severity-only gate and the LLM context-aware gate
  6. Scores both gates against examples/ground_truth.json
  7. Writes results/raw_results.json, results/metrics.csv, results/report.md

Usage:
    python3 run_evaluation.py
    python3 run_evaluation.py --skip-llm            # only run the baseline gate
    python3 run_evaluation.py --images gate-demo/low-risk gate-demo/dev-context-safe
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from src import pipeline, evaluator  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("run_evaluation")

ROOT = Path(__file__).resolve().parent

IMAGE_TO_DOCKERFILE_DIR = {
    "gate-demo/low-risk": "low-risk",
    "gate-demo/high-risk-unpatched": "high-risk-unpatched",
    "gate-demo/high-risk-patched": "high-risk-patched",
    "gate-demo/privileged-misconfig": "privileged-misconfig",
    "gate-demo/dev-context-safe": "dev-context-safe",
}


def load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--images-file", default="examples/deployment_context.json",
                         help="JSON file mapping image tag -> deployment context")
    parser.add_argument("--images", nargs="*", default=None,
                         help="Only run these image tags (default: all in --images-file)")
    parser.add_argument("--skip-llm", action="store_true",
                         help="Only run the severity-only baseline gate (no API key needed)")
    args = parser.parse_args()

    with open(ROOT / args.config, "r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh)

    context_map = load_json(ROOT / args.images_file)
    ground_truth = load_json(ROOT / config["paths"]["ground_truth_file"])
    ground_truth = {k: v for k, v in ground_truth.items() if not k.startswith("_")}

    enrichment_overrides_all = load_json(ROOT / "examples" / "enrichment_overrides.json")
    config_risk_overrides_all = load_json(ROOT / "examples" / "config_risk_overrides.json")

    images = args.images or list(context_map.keys())

    results = []
    for image in images:
        folder = IMAGE_TO_DOCKERFILE_DIR.get(image)
        if folder is None:
            logger.warning("No known Dockerfile folder for %s, skipping", image)
            continue
        dockerfile_path = ROOT / "examples" / "containers" / folder / "Dockerfile"

        logger.info("Running pipeline for %s ...", image)
        try:
            result = pipeline.run_pipeline_for_image(
                image=image,
                dockerfile_path=str(dockerfile_path),
                config=config,
                context_map=context_map,
                fixture_enrichment_overrides=enrichment_overrides_all.get(image),
                config_risk_override=config_risk_overrides_all.get(image),
                use_llm=not args.skip_llm,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Pipeline failed for %s: %s", image, exc)
            continue

        results.append(result)
        sev = result["severity_gate_result"]["decision"]
        llm = result["llm_gate_result"]["decision"] if result["llm_gate_result"] else "skipped"
        logger.info("  -> severity_gate=%s | llm_gate=%s | ground_truth=%s",
                    sev, llm, ground_truth.get(image, "?"))

    results_dir = ROOT / config["paths"]["results_dir"]
    evaluator.write_outputs(results, ground_truth, str(results_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
