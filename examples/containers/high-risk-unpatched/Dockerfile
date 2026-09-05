# PROFILE: high-risk-unpatched
# Old, unmaintained base image with known unpatched CVEs, deployed to
# internet-facing PRODUCTION (see deployment_context.json).
# Expected decision: BLOCK under both gates (this is the case where they should agree).

FROM debian:9

RUN apt-get update || true
WORKDIR /app
COPY hello.sh /app/hello.sh
RUN chmod +x /app/hello.sh

# Deliberately no USER directive -> runs as root, matching a common real-world mistake.
ENTRYPOINT ["/app/hello.sh"]
