"""
enrichment.py
-------------
Adds exploit-intelligence signals to each raw scanner finding:

- EPSS score: probability (0-1) that a CVE will be exploited in the wild in the
  next 30 days, from FIRST.org's Exploit Prediction Scoring System API.
- KEV flag: whether the CVE is in CISA's Known Exploited Vulnerabilities catalog
  (i.e. *confirmed* active exploitation, not just predicted).
- patch_available: derived directly from Trivy's FixedVersion field.

If network access to these feeds is unavailable (offline demo, exam room without
Wi-Fi, etc.), enrichment degrades gracefully to a neutral default rather than
crashing the pipeline -- this is logged so it's visible in your results.
"""

from __future__ import annotations

import logging
from typing import List

import requests

logger = logging.getLogger(__name__)


def _fetch_epss_scores(cve_ids: List[str], api_url: str, timeout: int) -> dict:
    """Batch-query EPSS for a list of CVE IDs. Returns {cve_id: epss_float}."""
    if not cve_ids:
        return {}
    scores = {}
    try:
        # FIRST.org API accepts comma-separated CVE list, capped conservatively per call.
        batch_size = 100
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            resp = requests.get(
                api_url,
                params={"cve": ",".join(batch)},
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
            for row in data:
                scores[row["cve"]] = float(row.get("epss", 0.0))
    except Exception as exc:  # noqa: BLE001 -- deliberately broad: enrichment must never crash the gate
        logger.warning("EPSS lookup failed (%s); defaulting affected CVEs to score 0.0", exc)
    return scores


def _fetch_kev_set(kev_feed_url: str, timeout: int) -> set:
    """Return the set of CVE IDs CISA lists as Known Exploited Vulnerabilities."""
    try:
        resp = requests.get(kev_feed_url, timeout=timeout)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        return {v["cveID"] for v in vulns}
    except Exception as exc:  # noqa: BLE001
        logger.warning("KEV feed lookup failed (%s); defaulting to empty KEV set", exc)
        return set()


def enrich_findings(findings: List[dict], config: dict) -> List[dict]:
    """
    Takes normalized scanner findings and returns a new list with added fields:
        epss_score (float, 0-1)
        kev_listed (bool)
        patch_available (bool)
        exploit_tier ("none" | "low" | "elevated" | "confirmed")
    """
    enrich_cfg = config["enrichment"]
    cve_ids = [f["cve_id"] for f in findings if f["cve_id"] != "UNKNOWN"]

    epss_scores = _fetch_epss_scores(cve_ids, enrich_cfg["epss_api_url"], enrich_cfg["request_timeout_seconds"])
    kev_set = _fetch_kev_set(enrich_cfg["kev_feed_url"], enrich_cfg["request_timeout_seconds"])

    warn_cut = enrich_cfg["epss_exploit_probability_warn"]
    high_cut = enrich_cfg["epss_exploit_probability_high"]

    enriched = []
    for f in findings:
        e = dict(f)
        epss = epss_scores.get(f["cve_id"], 0.0)
        kev = f["cve_id"] in kev_set
        e["epss_score"] = epss
        e["kev_listed"] = kev
        e["patch_available"] = bool(f.get("fixed_version"))

        if kev:
            e["exploit_tier"] = "confirmed"
        elif epss >= high_cut:
            e["exploit_tier"] = "elevated"
        elif epss >= warn_cut:
            e["exploit_tier"] = "low"
        else:
            e["exploit_tier"] = "none"

        enriched.append(e)
    return enriched


def expand_wildcard_overrides(findings: List[dict], image_overrides: dict) -> dict:
    """
    image_overrides may contain a special "_apply_to_all_found_cves" key whose value
    is applied to every CVE actually found by the scanner for that image (used by the
    example containers, where we don't know in advance exactly which CVE IDs a given
    base image will contain, but we do want a deterministic exploit-intel narrative).
    Explicit per-CVE-ID keys in image_overrides always take precedence.
    """
    wildcard = image_overrides.get("_apply_to_all_found_cves")
    expanded = {k: v for k, v in image_overrides.items() if not k.startswith("_")}
    if wildcard:
        for f in findings:
            expanded.setdefault(f["cve_id"], wildcard)
    return expanded


def enrich_from_fixture(findings: List[dict], fixture_overrides: dict) -> List[dict]:
    """
    Offline/demo path: apply a fixed dict of {cve_id: {epss_score, kev_listed}} instead
    of calling live APIs. Lets you fully control the "high risk unpatched vs already
    mitigated" narrative for your example containers without depending on real-time CVEs.
    """
    enriched = []
    for f in findings:
        e = dict(f)
        override = fixture_overrides.get(f["cve_id"], {})
        epss = override.get("epss_score", 0.0)
        kev = override.get("kev_listed", False)
        e["epss_score"] = epss
        e["kev_listed"] = kev
        e["patch_available"] = override.get("patch_available", bool(f.get("fixed_version")))

        if kev:
            e["exploit_tier"] = "confirmed"
        elif epss >= 0.50:
            e["exploit_tier"] = "elevated"
        elif epss >= 0.10:
            e["exploit_tier"] = "low"
        else:
            e["exploit_tier"] = "none"
        enriched.append(e)
    return enriched
