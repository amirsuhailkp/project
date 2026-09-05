"""
llm_gate.py
-----------
The PROPOSED gate from the abstract: a reasoning-based decision layer built on an
LLM. Takes the same underlying evidence as the severity gate (vulnerabilities)
PLUS exploit intelligence, config risk, and deployment context, and asks the
model to make a judgment call the way a human security analyst would --
including explaining *why*.

Talks to the model over the OpenAI-compatible chat completions API. This means
it works against:
  - a self-hosted FreeLLMAPI router (https://github.com/tashfeenahmed/freellmapi)
    -- point base_url at your local router (e.g. http://localhost:3001/v1) and
    use its unified "freellmapi-..." key, see config/config.yaml
  - OpenAI itself
  - any other OpenAI-compatible endpoint (Ollama, vLLM, LM Studio, OpenRouter, etc.)

The model is instructed to return strict JSON so the output is parseable and
auditable (important for a CI/CD gate: you need a machine-actionable decision,
not just prose).
"""

from __future__ import annotations

import json
import os
import time
from typing import List, Optional

from openai import OpenAI

VALID_DECISIONS = {"ALLOW", "WARN", "BLOCK"}

SYSTEM_PROMPT = """You are a senior application security analyst reviewing a container image \
before it is allowed to deploy through a CI/CD pipeline. You will be given:

1. A list of vulnerability findings from a scanner (Trivy), each with severity and CVSS score.
2. Exploit intelligence for each finding: an EPSS score (0-1 probability of exploitation in the \
next 30 days), whether it is in CISA's Known Exploited Vulnerabilities (KEV) catalog, and \
whether a patch/fixed version is already available.
3. Container configuration risk: whether it runs privileged, runs as root, has host-network \
enabled, mounts sensitive host paths (e.g. the Docker socket), or was granted extra Linux \
capabilities.
4. Deployment context: whether this is a production or development/staging deployment, and \
whether the service is exposed to the public internet.

Your job is to make the same judgment call an experienced security engineer would make -- not \
apply a fixed severity cutoff. Use reasoning like:
- A HIGH/CRITICAL severity CVE with no known exploit (low EPSS, not KEV-listed), where a patch \
is not yet available upstream, deployed to a non-internet-facing DEV environment, is lower \
real-world risk than a MEDIUM severity, KEV-listed vulnerability on an internet-facing \
PRODUCTION service.
- A container with almost no CVEs but running --privileged, as root, with the Docker socket \
mounted, exposed to the internet in production, is a severe risk regardless of CVE severity \
counts, because a single compromised process can pivot to full host control.
- Prefer BLOCK only when the combination of exploitability, reachability/exposure, and blast \
radius (config risk) is genuinely high. Use WARN for meaningful but not urgent risk that a human \
should review before deploying. Use ALLOW when risk is low or well-mitigated.
- Always weigh patch availability: an unpatched actively-exploited (KEV) vulnerability is much \
worse than a patchable one a team simply hasn't updated yet, especially in production.

Respond with ONLY a single JSON object, no markdown fences, no prose outside the JSON, in \
exactly this schema:
{
  "decision": "ALLOW" | "WARN" | "BLOCK",
  "justification": "2-4 sentences explaining the decision in terms of exploitability, \
reachability/exposure, and blast radius -- not just severity labels.",
  "risk_factors": ["short strings naming the specific CVE ids / config issues that drove the decision"]
}
"""


def _build_user_payload(findings: List[dict], config_risk: dict, deployment_context: dict) -> str:
    bundle = {
        "vulnerabilities": [
            {
                "cve_id": f["cve_id"],
                "package": f["package"],
                "severity": f["severity"],
                "cvss_score": f.get("cvss_score", 0.0),
                "patch_available": f.get("patch_available", bool(f.get("fixed_version"))),
                "epss_score": f.get("epss_score", 0.0),
                "kev_listed": f.get("kev_listed", False),
                "exploit_tier": f.get("exploit_tier", "unknown"),
            }
            for f in findings
        ],
        "config_risk": config_risk,
        "deployment_context": deployment_context,
    }
    return json.dumps(bundle, indent=2)


def _extract_json(text: str) -> Optional[dict]:
    text = (text or "").strip()
    # Strip accidental markdown fences -- smaller/free models ignore "no fences" far
    # more often than frontier models, so this path gets exercised a lot in practice.
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # last resort: find the outermost { ... } block (handles chatty preambles
        # like "Sure, here's the JSON:" that some free models prepend anyway)
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return None
        return None


def _make_client(config: dict) -> OpenAI:
    llm_cfg = config["llm_gate"]
    api_key_env = llm_cfg.get("api_key_env", "FREELLMAPI_API_KEY")
    api_key = os.environ.get(api_key_env)
    return OpenAI(base_url=llm_cfg["base_url"], api_key=api_key)


def decide(findings: List[dict], config_risk: dict, deployment_context: dict, config: dict,
           client: Optional[OpenAI] = None) -> dict:
    """
    Calls the LLM once and returns a normalized decision dict, matching the shape
    returned by severity_gate.decide() so the evaluator can treat both uniformly.
    """
    llm_cfg = config["llm_gate"]
    client = client or _make_client(config)

    user_payload = _build_user_payload(findings, config_risk, deployment_context)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_payload},
    ]

    start = time.time()
    response = client.chat.completions.create(
        model=llm_cfg["model"],
        max_tokens=llm_cfg["max_tokens"],
        temperature=llm_cfg["temperature"],
        messages=messages,
    )
    duration = time.time() - start

    text = response.choices[0].message.content or ""
    parsed = _extract_json(text)

    if parsed is None or parsed.get("decision") not in VALID_DECISIONS:
        # One retry with an explicit correction nudge, since CI/CD needs a parseable
        # decision. Free/smaller models drift from the schema more often than a
        # frontier model would, so this retry path matters more here.
        retry_start = time.time()
        response = client.chat.completions.create(
            model=llm_cfg["model"],
            max_tokens=llm_cfg["max_tokens"],
            temperature=0.0,
            messages=messages + [
                {"role": "assistant", "content": text},
                {"role": "user", "content": (
                    "Your previous response was not valid JSON matching the required schema. "
                    "Respond again with ONLY the JSON object, exactly matching the schema."
                )},
            ],
        )
        duration += time.time() - retry_start
        text = response.choices[0].message.content or ""
        parsed = _extract_json(text)

    if parsed is None or parsed.get("decision") not in VALID_DECISIONS:
        return {
            "gate": "llm_context_aware",
            "decision": "WARN",  # fail-safe: never silently ALLOW on a parse failure
            "justification": "LLM response could not be parsed as valid JSON after retry; "
                              "defaulting to WARN for manual review. Raw response logged.",
            "risk_factors": ["llm_parse_failure"],
            "latency_seconds": duration,
            "raw_response": text,
        }

    return {
        "gate": "llm_context_aware",
        "decision": parsed["decision"],
        "justification": parsed.get("justification", ""),
        "risk_factors": parsed.get("risk_factors", []),
        "latency_seconds": duration,
    }


def decide_with_consistency(findings: List[dict], config_risk: dict, deployment_context: dict,
                             config: dict, runs: Optional[int] = None) -> dict:
    """
    Runs decide() N times (config['llm_gate']['consistency_runs']) to measure decision
    consistency, since an LLM gate -- unlike the deterministic severity gate -- can vary
    run to run. This matters even more on FreeLLMAPI, since the router may fail over to
    a *different underlying model* between calls if one hits its free-tier rate limit.
    Returns the majority decision plus a consistency percentage.
    """
    n = runs or config["llm_gate"]["consistency_runs"]
    client = _make_client(config)

    results = [decide(findings, config_risk, deployment_context, config, client=client) for _ in range(n)]
    decisions = [r["decision"] for r in results]
    majority = max(set(decisions), key=decisions.count)
    consistency_pct = 100.0 * decisions.count(majority) / len(decisions)
    avg_latency = sum(r["latency_seconds"] for r in results) / len(results)

    primary = next(r for r in results if r["decision"] == majority)
    primary = dict(primary)
    primary["consistency_pct"] = consistency_pct
    primary["latency_seconds"] = avg_latency
    primary["all_runs"] = decisions
    return primary
