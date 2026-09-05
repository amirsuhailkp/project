"""
config_analyzer.py
-------------------
Extracts container CONFIGURATION risk that a pure vulnerability scanner never sees:
running privileged, running as root, dangerous host mounts (docker.sock, /etc,
/proc), and use of host networking. These are read either from:

  (a) a running/inspectable container via `docker inspect`, or
  (b) a static Dockerfile, via lightweight heuristic parsing (works without Docker
      running at all -- useful for pure static analysis / CI).

Schema returned:
{
    "runs_as_root": bool,
    "privileged": bool,
    "host_network": bool,
    "sensitive_mounts": [str, ...],
    "capabilities_added": [str, ...],
    "notes": [str, ...]
}
"""

from __future__ import annotations

import json
import re
import subprocess
from typing import List

SENSITIVE_MOUNT_PATTERNS = [
    r"/var/run/docker\.sock",
    r"^/etc(/|$)",
    r"^/proc(/|$)",
    r"^/sys(/|$)",
    r"^/$",           # whole root fs
    r"^/root(/|$)",
]


def _is_sensitive_path(path: str) -> bool:
    return any(re.match(p, path) for p in SENSITIVE_MOUNT_PATTERNS)


def analyze_dockerfile(dockerfile_path: str) -> dict:
    """Static heuristic analysis of a Dockerfile (no Docker daemon required)."""
    notes: List[str] = []
    runs_as_root = True  # default: Docker containers run as root unless USER is set
    privileged = False   # not expressible in a Dockerfile itself; inferred as False here
    host_network = False
    sensitive_mounts: List[str] = []
    capabilities_added: List[str] = []

    with open(dockerfile_path, "r", encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh.readlines()]

    last_user = None
    for ln in lines:
        if not ln or ln.startswith("#"):
            continue  # skip comments/blank lines -- only real instructions count as evidence
        if ln.upper().startswith("USER "):
            last_user = ln.split(None, 1)[1].strip()
        if ln.upper().startswith("VOLUME"):
            # VOLUME ["/var/run/docker.sock"] or VOLUME /var/run/docker.sock
            vol_str = ln[len("VOLUME"):].strip()
            for candidate in re.findall(r"[\"']?(/[\w\-/.]+)[\"']?", vol_str):
                if _is_sensitive_path(candidate):
                    sensitive_mounts.append(candidate)
        if "--cap-add" in ln:
            caps = re.findall(r"--cap-add[= ]([\w_]+)", ln)
            capabilities_added.extend(caps)
        if "--privileged" in ln:
            privileged = True
        if "--network=host" in ln or "--network host" in ln:
            host_network = True

    if last_user is not None and last_user.lower() not in ("root", "0"):
        runs_as_root = False
    else:
        notes.append("No non-root USER directive found (or explicitly set to root) -> runs as root.")

    if not sensitive_mounts:
        notes.append("No sensitive host mounts declared in Dockerfile.")

    return {
        "runs_as_root": runs_as_root,
        "privileged": privileged,
        "host_network": host_network,
        "sensitive_mounts": sorted(set(sensitive_mounts)),
        "capabilities_added": sorted(set(capabilities_added)),
        "notes": notes,
    }


def analyze_running_container(container_name_or_id: str) -> dict:
    """Live analysis via `docker inspect` for a container that has actually been created/run."""
    proc = subprocess.run(
        ["docker", "inspect", container_name_or_id],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"docker inspect failed for {container_name_or_id}: {proc.stderr.strip()}")

    data = json.loads(proc.stdout)[0]
    host_config = data.get("HostConfig", {})
    config = data.get("Config", {})

    user = config.get("User", "") or "root"
    runs_as_root = user in ("", "root", "0")
    privileged = bool(host_config.get("Privileged", False))
    network_mode = host_config.get("NetworkMode", "")
    host_network = network_mode == "host"
    capabilities_added = host_config.get("CapAdd") or []

    sensitive_mounts = []
    for mount in data.get("Mounts", []):
        src = mount.get("Source", "")
        if _is_sensitive_path(src):
            sensitive_mounts.append(src)

    notes = []
    if runs_as_root:
        notes.append("Container process runs as root inside the container.")
    if privileged:
        notes.append("Container started with --privileged (full host device/kernel access).")

    return {
        "runs_as_root": runs_as_root,
        "privileged": privileged,
        "host_network": host_network,
        "sensitive_mounts": sorted(set(sensitive_mounts)),
        "capabilities_added": sorted(set(capabilities_added)),
        "notes": notes,
    }
