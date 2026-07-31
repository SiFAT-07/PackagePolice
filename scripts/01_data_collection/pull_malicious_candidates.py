#!/usr/bin/env python3
"""
PackagePolice - Pull Malicious Candidates from OSV.dev
=========================================================
Downloads OSV's official bulk export for npm and PyPI (these include every
OSV record for that ecosystem - both traditional CVE-style advisories and
malicious-package reports - so this script filters for IDs starting with
"MAL-", which is OSV's convention for entries sourced from the malicious-
packages project (an aggregation of DataDog's dataset, Backstabber's Knife
Collection, GitHub's malware advisories, and the PyPI malware registry).

Source docs: https://google.github.io/osv.dev/data/
Bulk export: https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip

USAGE:
    python3 scripts/01_data_collection/pull_malicious_candidates.py \\
        --npm-count 650 --pypi-count 650 \\
        --output data/malicious_candidates.csv

NOTE: this script was written and syntax-verified against OSV's documented
export format, but the actual download could not be tested from the
sandbox used to build it (network policy there blocks
storage.googleapis.com). Test it for real in your VM, which has normal
internet access - and check the printed counts look sane before trusting
the output blindly.
"""

import argparse
import csv
import io
import json
import os
import random
import urllib.request
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
# OSV's ecosystem names are case-sensitive: "npm" (lowercase), "PyPI" (mixed case)
ECOSYSTEM_MAP = {"npm": "npm", "pypi": "PyPI"}

UA = {"User-Agent": "PackagePolice-research/1.0"}


def download_ecosystem_zip(eco_osv_name, cache_dir):
    cache_dir.mkdir(parents=True, exist_ok=True)
    zip_path = cache_dir / f"{eco_osv_name}_all.zip"
    if zip_path.exists():
        print(f"  Using cached {zip_path}")
        return zip_path
    url = f"{OSV_BASE}/{eco_osv_name}/all.zip"
    print(f"  Downloading {url} (this is the full ecosystem export, may be tens of MB)...")
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r, open(zip_path, "wb") as f:
        f.write(r.read())
    return zip_path


def extract_version_from_affected(affected_entry):
    """
    Prefer an explicit 'versions' list (exact affected versions - what we
    want for reproducible pinning). Fall back to the 'introduced' bound of
    a range only if no explicit versions list exists.
    """
    versions = affected_entry.get("versions")
    if versions:
        return versions[0]  # take the first listed affected version
    for rng in affected_entry.get("ranges", []):
        for event in rng.get("events", []):
            if "introduced" in event and event["introduced"] not in ("0", ""):
                return event["introduced"]
    return None


def parse_malicious_records(zip_path, ecosystem_out_name):
    records = []
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                data = json.loads(zf.read(name).decode("utf-8"))
            except Exception:
                continue
            if not data.get("id", "").startswith("MAL-"):
                continue
            for affected in data.get("affected", []):
                pkg = affected.get("package", {})
                pkg_name = pkg.get("name")
                if not pkg_name:
                    continue
                version = extract_version_from_affected(affected)
                if not version:
                    continue
                records.append((ecosystem_out_name, pkg_name, version))
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--npm-count", type=int, default=650)
    ap.add_argument("--pypi-count", type=int, default=650)
    ap.add_argument("--output", default=str(REPO_ROOT / "data" / "malicious_candidates.csv"))
    ap.add_argument("--seed", type=int, default=42, help="Random seed, for reproducible sampling")
    args = ap.parse_args()

    random.seed(args.seed)
    cache_dir = REPO_ROOT / "raw" / "osv_cache"

    wanted = {"npm": args.npm_count, "pypi": args.pypi_count}
    all_rows = []

    for eco_out, osv_name in ECOSYSTEM_MAP.items():
        print(f"[{eco_out}] fetching OSV export...")
        zip_path = download_ecosystem_zip(osv_name, cache_dir)
        records = parse_malicious_records(zip_path, eco_out)
        # Dedupe identical (ecosystem, name, version) triples
        records = list({(e, n, v) for e, n, v in records})
        print(f"  Found {len(records)} distinct malicious (package, version) pairs in {eco_out}.")
        random.shuffle(records)
        take = records[: wanted[eco_out]]
        if len(take) < wanted[eco_out]:
            print(f"  [WARN] Only found {len(take)}, fewer than the requested {wanted[eco_out]}.")
        all_rows.extend(take)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ecosystem", "package_name", "version", "label"])
        for eco, name, ver in all_rows:
            writer.writerow([eco, name, ver, "malicious"])

    print(f"\nWrote {len(all_rows)} malicious candidates to {args.output}")


if __name__ == "__main__":
    main()
