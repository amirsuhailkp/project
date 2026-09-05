"""
pipeline.py
-----------
Orchestrates a single image through: scan -> enrich -> config-analyze -> load context
-> run BOTH gates. This is the module `run_evaluation.py` calls in a loop over all
example images.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from . import config_analyzer, context_loader, enrichment, scanner, severity_gate, llm_gate

logger = logging.getLogger(__name__)


def run_pipeline_for_image(
    image: str,
    dockerfile_path: str,
    config: dict,
    context_map: dict,
    fixture_scan_path: Optional[str] = None,
    fixture_enrichment_overrides: Optional[dict] = None,
    config_risk_override: Optional[dict] = None,
    use_llm: bool = True,
) -> dict:
    """
    Runs one image through the full pipeline and returns:
    {
      "image": ...,
      "findings": [...],           # enriched findings
      "config_risk": {...},
      "deployment_context": {...},
      "severity_gate_result": {...},
      "llm_gate_result": {...} | None
    }
    """
    scanner_cfg = config["scanner"]

    if fixture_scan_path:
        scan_result = scanner.scan_from_fixture(fixture_scan_path, image_name=image)
    else:
        scan_result = scanner.scan_image(
            image,
            trivy_binary=scanner_cfg["trivy_binary"],
            severity_levels=scanner_cfg["severity_scan_levels"],
            timeout_seconds=scanner_cfg["trivy_timeout_seconds"],
        )

    if fixture_enrichment_overrides is not None:
        expanded = enrichment.expand_wildcard_overrides(scan_result.findings, fixture_enrichment_overrides)
        enriched = enrichment.enrich_from_fixture(scan_result.findings, expanded)
    else:
        enriched = enrichment.enrich_findings(scan_result.findings, config)

    config_risk = config_risk_override if config_risk_override else config_analyzer.analyze_dockerfile(dockerfile_path)
    deployment_context = context_loader.get_context(image, context_map)

    sev_result = severity_gate.decide(enriched, config)
    sev_result["latency_seconds"] += scan_result.scan_duration_seconds

    llm_result = None
    if use_llm:
        api_key_env = config["llm_gate"].get("api_key_env", "FREELLMAPI_API_KEY")
        if not os.environ.get(api_key_env):
            logger.warning("%s not set; skipping LLM gate for %s", api_key_env, image)
        else:
            llm_result = llm_gate.decide_with_consistency(enriched, config_risk, deployment_context, config)
            llm_result["latency_seconds"] += scan_result.scan_duration_seconds

    return {
        "image": image,
        "findings": enriched,
        "config_risk": config_risk,
        "deployment_context": deployment_context,
        "severity_gate_result": sev_result,
        "llm_gate_result": llm_result,
    }
