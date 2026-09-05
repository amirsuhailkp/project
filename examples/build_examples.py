#!/usr/bin/env python3
"""
build_examples.py
------------------
Builds all 5 example container images used by run_evaluation.py.
Run from anywhere; paths are resolved relative to this file.

Usage:
    python3 examples/build_examples.py
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTAINERS_DIR = HERE / "containers"

IMAGES = {
    "gate-demo/low-risk": "low-risk",
    "gate-demo/high-risk-unpatched": "high-risk-unpatched",
    "gate-demo/high-risk-patched": "high-risk-patched",
    "gate-demo/privileged-misconfig": "privileged-misconfig",
    "gate-demo/dev-context-safe": "dev-context-safe",
}


def main() -> int:
    for tag, folder in IMAGES.items():
        build_dir = CONTAINERS_DIR / folder
        print(f"\n=== Building {tag} from {build_dir} ===")
        result = subprocess.run(
            ["docker", "build", "-t", tag, str(build_dir)],
            check=False,
        )
        if result.returncode != 0:
            print(f"!! Failed to build {tag}", file=sys.stderr)
            return result.returncode
    print("\nAll 5 example images built successfully.")
    print("Run `docker images | grep gate-demo` to confirm.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
