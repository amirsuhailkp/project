"""
scanner.py
----------
Thin wrapper around the Trivy CLI. Runs a vulnerability scan against a container
image and normalizes the (fairly verbose) Trivy JSON output into a compact list
of findings that the rest of the pipeline can work with.

Normalized finding schema:
{
    "cve_id": "CVE-2023-1234",
    "package": "openssl",
    "installed_version": "1.1.1k-1",
    "fixed_version": "1.1.1n-1",     # empty string if no fix available yet
    "severity": "HIGH",
    "cvss_score": 7.5,               # float, 0.0 if not reported
    "title": "short description from trivy"
}
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import List


class ScannerError(RuntimeError):
    pass


@dataclass
class ScanResult:
    image: str
    findings: List[dict] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    raw: dict = field(default_factory=dict)


def _trivy_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def _severity_to_cvss(vuln: dict) -> float:
    """Trivy nests CVSS scores under multiple possible vendors; take the best available."""
    cvss = vuln.get("CVSS", {})
    for vendor in ("nvd", "redhat", "ghsa"):
        entry = cvss.get(vendor)
        if entry:
            score = entry.get("V3Score") or entry.get("V2Score")
            if score:
                return float(score)
    return 0.0


def _normalize(raw_json: dict) -> List[dict]:
    findings = []
    for result in raw_json.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "cve_id": vuln.get("VulnerabilityID", "UNKNOWN"),
                "package": vuln.get("PkgName", "unknown"),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "severity": vuln.get("Severity", "UNKNOWN").upper(),
                "cvss_score": _severity_to_cvss(vuln),
                "title": vuln.get("Title") or vuln.get("Description", "")[:140],
            })
    return findings


def scan_image(image: str, trivy_binary: str = "trivy",
                severity_levels: str = "LOW,MEDIUM,HIGH,CRITICAL",
                timeout_seconds: int = 300) -> ScanResult:
    """
    Run `trivy image` against the given tag/reference and return normalized findings.
    Raises ScannerError if trivy is missing or the scan fails.
    """
    if not _trivy_available(trivy_binary):
        raise ScannerError(
            f"'{trivy_binary}' not found on PATH. Install Trivy: "
            "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        )

    cmd = [
        trivy_binary, "image",
        "--format", "json",
        "--severity", severity_levels,
        "--quiet",
        image,
    ]

    start = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_seconds, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"Trivy scan of {image} timed out after {timeout_seconds}s") from exc
    duration = time.time() - start

    if proc.returncode not in (0, 1):  # trivy uses 1 for "vulnerabilities found" with --exit-code, else 0
        raise ScannerError(f"Trivy failed on {image}: {proc.stderr.strip()}")

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScannerError(f"Could not parse Trivy output for {image}: {exc}") from exc

    return ScanResult(
        image=image,
        findings=_normalize(raw),
        scan_duration_seconds=duration,
        raw=raw,
    )


def scan_from_fixture(fixture_path: str, image_name: str = "fixture") -> ScanResult:
    """Load a pre-recorded Trivy JSON fixture instead of invoking the real binary.
    Used by tests and by anyone demoing the pipeline without Trivy installed."""
    with open(fixture_path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return ScanResult(image=image_name, findings=_normalize(raw), scan_duration_seconds=0.0, raw=raw)
