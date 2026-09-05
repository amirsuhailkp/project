# Context-Aware Container Security Gate (LLM-Driven CI/CD Gating)

Final year B.Tech project implementation matching the abstract:

> A context-aware container security gate that replaces static severity checks with a
> reasoning-based decision layer built on an LLM. Vulnerability scan results (Trivy) are
> enriched with exploit intelligence and patch status, combined with container configuration
> risk (privileged mode, root execution, sensitive mounts) and deployment context
> (prod/dev, internet exposure). The LLM outputs ALLOW / WARN / BLOCK with a
> natural-language justification. This is benchmarked against a traditional severity-only gate
> on decision accuracy, false-positive block rate, decision consistency, and latency.

---

## 1. What's in this project

```
context-aware-gate/
├── README.md                      <- you are here
├── requirements.txt
├── config/
│   └── config.yaml                <- thresholds, model name, weights
├── src/
│   ├── scanner.py                 <- Trivy wrapper -> normalized findings
│   ├── enrichment.py               <- EPSS exploit score + patch status
│   ├── config_analyzer.py          <- privileged/root/mount risk from Dockerfile or docker inspect
│   ├── context_loader.py           <- loads deployment_context.json (env, internet exposure)
│   ├── severity_gate.py            <- BASELINE: traditional fixed-threshold gate
│   ├── llm_gate.py                 <- PROPOSED: LLM reasoning-based gate (Claude via Anthropic API)
│   ├── pipeline.py                 <- orchestrates one image through both gates
│   └── evaluator.py                <- runs the full benchmark, computes metrics, writes CSV/JSON
├── examples/
│   ├── containers/                 <- 5 example Dockerfiles, one per risk profile
│   │   ├── low-risk/
│   │   ├── high-risk-unpatched/
│   │   ├── high-risk-patched/
│   │   ├── privileged-misconfig/
│   │   └── dev-context-safe/
│   ├── deployment_context.json     <- per-image env/exposure metadata
│   └── ground_truth.json           <- expert-labeled "correct" decision per image, for accuracy scoring
├── tests/
│   └── test_pipeline.py            <- unit tests with mocked scanner/LLM (no network needed)
└── run_evaluation.py               <- single entry point: builds images, scans, gates, scores, reports
```

## 2. How the two gates differ (the core of your paper)

**Severity gate (baseline)** — `src/severity_gate.py`
Blocks if *any* finding's CVSS severity ≥ threshold (default: HIGH). Ignores exploitability,
patch availability, whether the container is even reachable, and whether it's prod or dev.
This is what most CI/CD scanners (Trivy `--exit-code`, Snyk severity gate, etc.) do today.

**LLM gate** — `src/llm_gate.py`
Sends the model a structured JSON bundle per image:
- vulnerability list (CVE id, package, severity, CVSS score)
- enrichment (EPSS exploit-probability score, "patch available: yes/no", KEV-listed: yes/no)
- config risk (`privileged: true/false`, `runs_as_root: true/false`, sensitive mounts list)
- deployment context (`environment: prod/dev`, `internet_facing: true/false`)

The model must return strict JSON: `{"decision": "ALLOW|WARN|BLOCK", "justification": "...", "risk_factors": [...]}`.
`src/llm_gate.py` parses and validates this, and retries once on malformed output.

This gate talks to the model over the standard **OpenAI-compatible chat completions API**
(`/v1/chat/completions`), so it works against any OpenAI-compatible endpoint — including a
self-hosted **[FreeLLMAPI](https://github.com/tashfeenahmed/freellmapi)** router, which is what
this project is configured for by default (see step 3 below).

**Why this matters for your results section:** a HIGH-severity CVE with no public exploit,
a patch not yet needed because the vulnerable code path is unreachable, in a `dev`,
non-internet-facing container should be **ALLOW** or **WARN** under the LLM gate but is an
automatic **BLOCK** under the severity gate — this is your "false-positive block" example.
Conversely, a MEDIUM-severity CVE that is actively exploited (KEV-listed) on a
privileged, internet-facing **prod** container should be **BLOCK** under the LLM gate even
though the severity gate might let it through with a lenient threshold — this is your
"insufficient scrutiny" example.

## 3. Prerequisites

- Python 3.10+
- Docker (to build the 5 example images, and to self-host FreeLLMAPI)
- [Trivy](https://aquasecurity.github.io/trivy/) installed and on your `PATH`
  - macOS: `brew install trivy`
  - Ubuntu/Debian: see https://aquasecurity.github.io/trivy/latest/getting-started/installation/
  - Or run it via Docker itself: `docker pull aquasec/trivy`
- A running **[FreeLLMAPI](https://github.com/tashfeenahmed/freellmapi)** router (self-hosted,
  free-tier LLM aggregator behind one OpenAI-compatible `/v1` endpoint) — see step 3 below
- Internet access at run time (Trivy needs its vuln DB, EPSS needs its API, the LLM gate needs
  your FreeLLMAPI router, which itself needs internet access to reach the free providers)

## 4. Step-by-step setup

### Step 1 — Get the code and install dependencies
```bash
cd context-aware-gate
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2 — Stand up FreeLLMAPI (your LLM backend)
This project talks to the model over the OpenAI-compatible `/v1/chat/completions` API, so any
compatible server works — but it's set up by default for a self-hosted FreeLLMAPI router:

```bash
curl -fsSL https://freellmapi.co/install.sh | bash
```
This pulls the Docker image and starts the router. Then:
1. Open http://localhost:3001, sign up for the local dashboard account.
2. On the **Keys** page, add at least one free provider key (e.g. Groq, Google, Mistral, OpenRouter
   — see the router's README for the full list of 34 free providers) and copy the **unified key**
   shown at the top of that page (looks like `freellmapi-...`).
3. (Optional) Reorder the **Fallback Chain** to prefer faster/more capable free models first.

Set the unified key as an environment variable:
```bash
export FREELLMAPI_API_KEY="freellmapi-..."     # Windows (PowerShell): $env:FREELLMAPI_API_KEY="freellmapi-..."
```

If your router runs somewhere other than `http://localhost:3001`, update `base_url` in
`config/config.yaml` under `llm_gate:` accordingly. `model: "auto"` in that same section lets
FreeLLMAPI's smart routing pick the best available free model per request; you can pin an exact
model id from your router's `/v1/models` list instead if you want reproducible model choice
across runs (useful for a "same model every time" claim in your evaluation chapter).

### Step 3 — Confirm Trivy works
```bash
trivy --version
trivy image alpine:3.18       # sanity check, downloads the vuln DB on first run
```

### Step 4 — Build the 5 example container images
```bash
python3 examples/build_examples.py
```
This builds:
| Image tag | Risk profile |
|---|---|
| `gate-demo/low-risk` | Minimal, patched, non-root, dev context |
| `gate-demo/high-risk-unpatched` | Old base image, known unpatched CVEs, internet-facing prod |
| `gate-demo/high-risk-patched` | Same CVEs present in scan DB metadata but patch already applied / unreachable path, prod |
| `gate-demo/privileged-misconfig` | Few/no CVEs but runs privileged + root + mounts docker.sock, prod, internet-facing |
| `gate-demo/dev-context-safe` | Has a HIGH CVE, but dev environment, not internet-facing, no exploit in the wild |

### Step 5 — Run the full evaluation
```bash
python3 run_evaluation.py --images-file examples/deployment_context.json
```
This will, per image:
1. Run Trivy → normalized findings (`src/scanner.py`)
2. Enrich findings with EPSS score + patch status (`src/enrichment.py`)
3. Analyze config risk (`src/config_analyzer.py`)
4. Load deployment context (`src/context_loader.py`)
5. Run the **severity gate** and the **LLM gate** on the same bundle
6. Repeat the LLM gate 3× per image (consistency check) and time both gates (latency)
7. Compare each gate's decision against `examples/ground_truth.json`

Results land in `results/`:
- `results/raw_results.json` — every decision, justification, and timing
- `results/metrics.csv` — accuracy, false-positive block rate, consistency %, avg latency per gate
- `results/report.md` — auto-generated summary table + narrative, ready to paste into your report

### Step 6 (optional) — Run without Docker/Trivy installed
`tests/test_pipeline.py` uses fixture JSON (`tests/fixtures/`) instead of a live scanner, so you
can demo the LLM reasoning layer and the metrics pipeline before your Docker/Trivy setup is ready:
```bash
pytest tests/ -v
```

## 5. A note on using free-tier models via FreeLLMAPI

FreeLLMAPI stacks free tiers from ~34 providers behind one endpoint with automatic failover — this
is great for a zero-cost student project, but worth being upfront about in your report:

- **Model identity can vary between calls.** If a provider's free tier is rate-limited, the router
  fails over to a different underlying model. This directly affects the **decision consistency**
  metric — a "consistency" dip on FreeLLMAPI may reflect a model switch mid-benchmark rather than
  the same model reasoning differently. Pin an exact `model:` in `config/config.yaml` (instead of
  `"auto"`) if you want to control for this in your results, and mention which you chose.
- **Free models are generally less capable than frontier models** at strictly following a JSON
  schema — this is exactly why `llm_gate.py` has a retry-on-malformed-JSON path and a fail-safe
  WARN default; expect to see that path exercised more often than it would be with a frontier
  model, and consider reporting how often the retry triggered as part of your results.
- **Latency is more variable** than a dedicated paid API, since requests may hit different
  providers with different response times.
- Per FreeLLMAPI's own disclaimer, this stack is for personal experimentation/learning, not
  production — appropriate framing for a final-year project, but worth citing if your report
  discusses production-readiness.

## 6. Metrics definitions (for your evaluation chapter)

- **Decision accuracy** — % of images where the gate's decision matches `ground_truth.json`.
- **False-positive block rate** — % of images labeled `ALLOW`/`WARN` in ground truth that the gate BLOCKED.
- **Decision consistency** — for the LLM gate, run the same input N=3 times; % of runs returning the
  same decision as the majority vote (the severity gate is deterministic, so its consistency is always 100%
  — a useful point to discuss as a trade-off in your report).
- **Processing latency** — wall-clock seconds for scan+enrich+decide, averaged per gate per image.

## 7. Extending this for your report

- Swap in more base images / real CVEs by editing the Dockerfiles in `examples/containers/`.
- Adjust `config/config.yaml` to change severity threshold, EPSS cutoff, or the LLM model/router.
- The LLM prompt template lives in `src/llm_gate.py::SYSTEM_PROMPT` — this is worth including
  verbatim as an appendix/figure in your report since reviewers will want to see the reasoning schema.
- To test statistical significance across a larger image set, add more entries to
  `deployment_context.json` and `ground_truth.json`.
- Because `llm_gate.py` only depends on the OpenAI-compatible chat completions interface, you can
  swap FreeLLMAPI for a paid API later (OpenAI, or Anthropic via an OpenAI-compat shim) just by
  changing `base_url`/`api_key_env` in `config/config.yaml` — no code changes needed.
