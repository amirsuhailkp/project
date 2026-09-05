# PROFILE: dev-context-safe
# Has a genuine HIGH severity CVE (by CVSS score), but it's deployed to a DEV
# environment, not internet-facing, no public exploit exists (low EPSS, not KEV).
# Expected decision: severity gate -> BLOCK (context-blind). LLM gate -> ALLOW or WARN.
# *** Second "false-positive block" demonstration case, using environment context
#     rather than patch status as the mitigating factor. ***

FROM node:18-alpine

RUN adduser -D -u 10003 devuser
WORKDIR /app
COPY hello.sh /app/hello.sh
RUN chmod +x /app/hello.sh && chown devuser:devuser /app/hello.sh

USER devuser
ENTRYPOINT ["/app/hello.sh"]
