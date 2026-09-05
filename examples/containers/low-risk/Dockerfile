# PROFILE: low-risk
# Minimal, patched, non-root, no sensitive mounts. Deployed to dev in
# deployment_context.json. Expected decision: ALLOW under both gates.

FROM alpine:3.20

RUN adduser -D -u 10001 appuser
WORKDIR /app
COPY hello.sh /app/hello.sh
RUN chmod +x /app/hello.sh && chown appuser:appuser /app/hello.sh

USER appuser
ENTRYPOINT ["/app/hello.sh"]
