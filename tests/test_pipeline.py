"""
test_pipeline.py
-----------------
Unit tests that exercise the scanner normalization, severity gate, config
analyzer, and LLM gate parsing logic WITHOUT requiring Docker, Trivy, network
access, or a real Anthropic API key. This is what to run in a classroom/exam
environment, or in CI, to prove the pipeline logic works before the live demo.

Run with:  pytest tests/ -v
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import scanner, severity_gate, config_analyzer, enrichment, llm_gate  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def config():
    with open(ROOT / "config" / "config.yaml", "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------- scanner ----------

def test_scan_from_fixture_normalizes_high_severity():
    result = scanner.scan_from_fixture(str(FIXTURES / "high_severity_scan.json"), image_name="test")
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["cve_id"] == "CVE-2021-99999"
    assert f["severity"] == "CRITICAL"
    assert f["cvss_score"] == 9.8
    assert f["fixed_version"] == ""


def test_scan_from_fixture_empty_findings():
    result = scanner.scan_from_fixture(str(FIXTURES / "low_severity_scan.json"), image_name="test")
    assert result.findings == []


# ---------- severity gate ----------

def test_severity_gate_blocks_on_critical(config):
    findings = scanner.scan_from_fixture(str(FIXTURES / "high_severity_scan.json")).findings
    result = severity_gate.decide(findings, config)
    assert result["decision"] == "BLOCK"


def test_severity_gate_allows_on_no_findings(config):
    result = severity_gate.decide([], config)
    assert result["decision"] == "ALLOW"


def test_severity_gate_is_context_blind(config):
    """The whole point of the baseline: same CVE -> same decision regardless of
    exploitability or environment, since severity_gate.decide() doesn't even
    accept those parameters."""
    findings = scanner.scan_from_fixture(str(FIXTURES / "high_severity_scan.json")).findings
    result_prod = severity_gate.decide(findings, config)
    result_dev = severity_gate.decide(findings, config)  # no context param exists to vary
    assert result_prod["decision"] == result_dev["decision"] == "BLOCK"


# ---------- config analyzer ----------

def test_config_analyzer_detects_non_root_user(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine\nUSER 10001\nCMD [\"true\"]\n")
    risk = config_analyzer.analyze_dockerfile(str(dockerfile))
    assert risk["runs_as_root"] is False


def test_config_analyzer_defaults_to_root_when_no_user(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM alpine\nCMD [\"true\"]\n")
    risk = config_analyzer.analyze_dockerfile(str(dockerfile))
    assert risk["runs_as_root"] is True


def test_config_analyzer_flags_docker_socket_mount(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text('FROM alpine\nVOLUME ["/var/run/docker.sock"]\nCMD ["true"]\n')
    risk = config_analyzer.analyze_dockerfile(str(dockerfile))
    assert "/var/run/docker.sock" in risk["sensitive_mounts"]


# ---------- enrichment (fixture path, no live API calls) ----------

def test_enrich_from_fixture_marks_kev_and_exploit_tier():
    findings = [{"cve_id": "CVE-2021-99999", "package": "openssl", "installed_version": "1",
                 "fixed_version": "", "severity": "CRITICAL", "cvss_score": 9.8, "title": "x"}]
    overrides = {"CVE-2021-99999": {"epss_score": 0.9, "kev_listed": True, "patch_available": False}}
    enriched = enrichment.enrich_from_fixture(findings, overrides)
    assert enriched[0]["exploit_tier"] == "confirmed"
    assert enriched[0]["kev_listed"] is True


def test_expand_wildcard_overrides_applies_to_all_findings():
    findings = [
        {"cve_id": "CVE-A", "package": "p1", "installed_version": "1", "fixed_version": "",
         "severity": "HIGH", "cvss_score": 7.0, "title": "x"},
        {"cve_id": "CVE-B", "package": "p2", "installed_version": "1", "fixed_version": "",
         "severity": "MEDIUM", "cvss_score": 5.0, "title": "y"},
    ]
    image_overrides = {"_apply_to_all_found_cves": {"epss_score": 0.02, "kev_listed": False, "patch_available": True}}
    expanded = enrichment.expand_wildcard_overrides(findings, image_overrides)
    assert expanded["CVE-A"]["epss_score"] == 0.02
    assert expanded["CVE-B"]["patch_available"] is True


# ---------- LLM gate: JSON parsing / validation logic (mocked OpenAI-compatible API) ----------

class _FakeMessage:
    def __init__(self, text):
        self.content = text


class _FakeChoice:
    def __init__(self, text):
        self.message = _FakeMessage(text)


class _FakeResponse:
    def __init__(self, text):
        self.choices = [_FakeChoice(text)]


def test_llm_gate_parses_well_formed_json(config):
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _FakeResponse(
        '{"decision": "WARN", "justification": "Patched, low exploit likelihood.", '
        '"risk_factors": ["CVE-2021-99999"]}'
    )
    findings = scanner.scan_from_fixture(str(FIXTURES / "high_severity_scan.json")).findings
    result = llm_gate.decide(findings, {"privileged": False}, {"environment": "dev"}, config, client=fake_client)
    assert result["decision"] == "WARN"
    assert "CVE-2021-99999" in result["risk_factors"]


def test_llm_gate_retries_and_falls_back_to_warn_on_bad_json(config):
    fake_client = MagicMock()
    # Both the first call and the retry return unparseable text -- this is more
    # common with small free models than with a frontier model, hence the retry path.
    fake_client.chat.completions.create.side_effect = [
        _FakeResponse("I think this looks fine, no JSON here."),
        _FakeResponse("still not json"),
    ]
    findings = []
    result = llm_gate.decide(findings, {"privileged": False}, {"environment": "dev"}, config, client=fake_client)
    assert result["decision"] == "WARN"
    assert "llm_parse_failure" in result["risk_factors"]
    assert fake_client.chat.completions.create.call_count == 2


def test_llm_gate_strips_markdown_fences(config):
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = _FakeResponse(
        '```json\n{"decision": "BLOCK", "justification": "Privileged + KEV.", "risk_factors": ["cfg"]}\n```'
    )
    result = llm_gate.decide([], {"privileged": True}, {"environment": "prod"}, config, client=fake_client)
    assert result["decision"] == "BLOCK"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
