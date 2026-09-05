# PROFILE: privileged-misconfig
# Very few / no CVEs in the image itself, but the run configuration is dangerous:
# runs privileged, as root, mounts the Docker socket. Internet-facing PRODUCTION.
# Expected decision: severity gate -> ALLOW (it only looks at CVEs!). LLM gate -> BLOCK.
# *** This is your "insufficient scrutiny of dangerous configs" demonstration case. ***
#
# NOTE: --privileged and the docker.sock mount are RUNTIME flags, not something a
# Dockerfile can declare on its own -- they are recorded here as comments AND in
# config_risk_override.json (used by config_analyzer heuristics / docker inspect
# in the live-container path) so the config_analyzer step reflects the true run
# profile without you needing to actually run this container privileged during
# grading/demo.
#
# Real run command this profile models:
#   docker run --privileged --user root \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     --network host \
#     gate-demo/privileged-misconfig

FROM alpine:3.20

WORKDIR /app
COPY hello.sh /app/hello.sh
RUN chmod +x /app/hello.sh
# Deliberately root, deliberately no dropped capabilities.
ENTRYPOINT ["/app/hello.sh"]
