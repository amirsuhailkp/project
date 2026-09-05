# PROFILE: high-risk-patched
# Scanner will still flag HIGH severity CVEs by CVSS score, but this project's
# enrichment fixture (examples/enrichment_overrides.json) marks these specific
# CVEs as patch_available=true / low EPSS / not KEV-listed -- i.e. a fix exists
# and there's no active exploitation, so a human reviewer would not block on it.
# Deployed to PRODUCTION but not internet-facing (internal service).
# Expected decision: severity gate -> BLOCK (context-blind). LLM gate -> WARN or ALLOW.
# *** This is one of your key "false-positive block" demonstration cases. ***

FROM debian:11-slim

RUN groupadd -g 10002 appgroup && useradd -u 10002 -g appgroup -m appuser
WORKDIR /app
COPY hello.sh /app/hello.sh
RUN chmod +x /app/hello.sh && chown appuser:appgroup /app/hello.sh

USER appuser
ENTRYPOINT ["/app/hello.sh"]
