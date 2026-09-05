"""
context_loader.py
------------------
Loads deployment-context metadata for each image: is this going to production or a
dev/staging environment, and is it internet-facing. In a real pipeline this would
come from your CD manifests / Kubernetes namespace labels / Helm values; here it's
a simple JSON file per image so the whole project can be run without a real cluster.
"""

from __future__ import annotations

import json
from typing import Dict


def load_context_map(path: str) -> Dict[str, dict]:
    """
    deployment_context.json shape:
    {
      "gate-demo/low-risk": {"environment": "dev", "internet_facing": false, "namespace": "sandbox"},
      ...
    }
    """
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def get_context(image: str, context_map: Dict[str, dict]) -> dict:
    return context_map.get(image, {
        "environment": "unknown",
        "internet_facing": True,   # fail safe: assume the worst if context is missing
        "namespace": "unknown",
    })
