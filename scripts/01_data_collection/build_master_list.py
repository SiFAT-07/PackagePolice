#!/usr/bin/env python3
"""
PackagePolice - Build Master List
====================================
Merges data/benign_candidates.csv + data/malicious_candidates.csv into
one shuffled, deduplicated data/master_list.csv - the file
universal_collect.py's --list argument expects.

USAGE:
    python3 scripts/01_data_collection/build_master_list.py
"""

import csv
import random
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DATA_DIR = REPO_ROOT / "data"


def main():
    rows = []
    seen = set()
    for fname in ["benign_candidates.csv", "malicious_candidates.csv"]:
        path = DATA_DIR / fname
        if not path.exists():
            print(f"[WARN] {path} not found, skipping.")
            continue
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                key = (row["ecosystem"], row["package_name"], row["version"])
                if key in seen:
                    continue
                seen.add(key)
                rows.append(row)

    random.Random(42).shuffle(rows)

    out_path = DATA_DIR / "master_list.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ecosystem", "package_name", "version", "label"])
        writer.writeheader()
        writer.writerows(rows)

    benign_n = sum(1 for r in rows if r["label"] == "benign")
    malicious_n = sum(1 for r in rows if r["label"] == "malicious")
    print(f"Wrote {len(rows)} rows to {out_path}")
    print(f"  benign: {benign_n}  malicious: {malicious_n}  ratio: 1:{benign_n/malicious_n:.2f}" if malicious_n else "")


if __name__ == "__main__":
    main()
