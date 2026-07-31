#!/usr/bin/env python3
"""
PackagePolice - Pull Benign Candidates
=========================================
Builds a diverse pool of benign candidate packages for both ecosystems.

PyPI: hugovk/top-pypi-packages - a live, monthly-updated dump of the
15,000 most-downloaded PyPI packages by real download count. Tested
working via the raw.githubusercontent.com mirror of that repo.

npm: the npm registry's own official search API
(registry.npmjs.org/-/v1/search), queried with a spread of common search
terms rather than one single query. This is a deliberate choice: a
single query (even a very generic one) returns results biased toward
whatever that specific term matches best, which would make the "benign"
pool suspiciously narrow. Spreading across many unrelated terms gives
better topical diversity - closer to a real cross-section of the
ecosystem instead of one popularity list's blind spots.

IMPORTANT DESIGN NOTE: candidates are sampled from a WIDE range of the
available pool (not just the single most popular packages), on purpose.
If every benign example were an extremely famous, extremely healthy
package (huge stars, huge downloads, ancient account age), the model
could learn "high popularity = benign" as a shortcut instead of
learning the actual signal patterns - that shortcut would fall apart on
any real, less-famous benign package it's asked to judge later.

USAGE:
    python3 scripts/01_data_collection/pull_benign_candidates.py \\
        --npm-count 1950 --pypi-count 1950 \\
        --output data/benign_candidates.csv
"""

import argparse
import csv
import os
import random
import time
import urllib.parse
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
UA = {"User-Agent": "PackagePolice-research/1.0"}

PYPI_TOP_LIST_URL = "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json"

# Deliberately broad, unrelated search terms for npm topical diversity -
# spans web frameworks, CLI tooling, data/ML, testing, build tooling, etc.
# so the benign pool isn't just "whatever's most globally popular."
NPM_SEARCH_TERMS = [
    "react", "vue", "express", "webpack", "eslint", "babel", "jest", "axios",
    "lodash", "typescript", "graphql", "redux", "mongoose", "socket", "cli",
    "parser", "logger", "validator", "queue", "cache", "auth", "config",
    "markdown", "image", "date", "crypto", "stream", "test", "build", "lint",
]


def http_json(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        import json
        return json.loads(r.read().decode())


def get_pypi_candidates(count, seed):
    print("[pypi] fetching hugovk/top-pypi-packages ...")
    data = http_json(PYPI_TOP_LIST_URL)
    names = [row["project"] for row in data["rows"]]
    print(f"  {len(names)} packages available in the top-download list.")
    random.Random(seed).shuffle(names)
    return names[:count]


def get_npm_candidates(count, seed):
    print("[npm] querying registry search across", len(NPM_SEARCH_TERMS), "terms ...")
    seen = set()
    for term in NPM_SEARCH_TERMS:
        url = f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(term)}&size=100"
        try:
            data = http_json(url)
        except Exception as e:
            print(f"  [WARN] query '{term}' failed: {e}")
            continue
        for obj in data.get("objects", []):
            seen.add(obj["package"]["name"])
        time.sleep(1.0)
    names = list(seen)
    print(f"  {len(names)} distinct package names gathered across all queries.")
    random.Random(seed).shuffle(names)
    return names[:count]


def resolve_latest_version_npm(name):
    try:
        data = http_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='')}")
        return data.get("dist-tags", {}).get("latest")
    except Exception:
        return None


def resolve_latest_version_pypi(name):
    try:
        data = http_json(f"https://pypi.org/pypi/{name}/json")
        return data.get("info", {}).get("version")
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--npm-count", type=int, default=1950)
    ap.add_argument("--pypi-count", type=int, default=1950)
    ap.add_argument("--output", default=str(REPO_ROOT / "data" / "benign_candidates.csv"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    pypi_names = get_pypi_candidates(args.pypi_count, args.seed)
    npm_names = get_npm_candidates(args.npm_count, args.seed)

    rows = []
    print(f"\nResolving current versions for {len(pypi_names)} PyPI + {len(npm_names)} npm packages ...")
    for i, name in enumerate(pypi_names, 1):
        ver = resolve_latest_version_pypi(name)
        if ver:
            rows.append(("pypi", name, ver, "benign"))
        if i % 200 == 0:
            print(f"  pypi: {i}/{len(pypi_names)}")
        time.sleep(0.1)

    for i, name in enumerate(npm_names, 1):
        ver = resolve_latest_version_npm(name)
        if ver:
            rows.append(("npm", name, ver, "benign"))
        if i % 200 == 0:
            print(f"  npm: {i}/{len(npm_names)}")
        time.sleep(0.1)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ecosystem", "package_name", "version", "label"])
        writer.writerows(rows)

    print(f"\nWrote {len(rows)} benign candidates to {args.output}")


if __name__ == "__main__":
    main()
