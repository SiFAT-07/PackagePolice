#!/usr/bin/env python3
"""safe_collect.py

Lightweight collector that scores package names using several signal modules
and places metadata into `dataset/` or `quarantine/` depending on score.

This is intentionally conservative and does not fetch or execute package code.
"""
import argparse
import json
import os
from pathlib import Path
from scripts.signals import signal1, signal2, signal3, signal4, signal5


DATA_DIR = Path(__file__).resolve().parents[1] / "dataset"
QUARANTINE_DIR = Path(__file__).resolve().parents[1] / "quarantine"
LOGS_DIR = Path(__file__).resolve().parents[1] / "logs"


def score_name(name: str) -> float:
    scores = [signal1(name), signal2(name), signal3(name), signal4(name), signal5(name)]
    return sum(scores) / len(scores)


def save_metadata(name: str, metadata: dict):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    out = DATA_DIR / f"{name}.json"
    with open(out, "w") as f:
        json.dump(metadata, f, indent=2)


def quarantine(name: str, reason: str):
    qdir = QUARANTINE_DIR / "pypi" / "malicious"
    qdir.mkdir(parents=True, exist_ok=True)
    path = qdir / f"{name}.txt"
    with open(path, "w") as f:
        f.write(reason + "\n")


def process(name: str, threshold: float = 0.6):
    s = score_name(name)
    meta = {"name": name, "score": s}
    save_metadata(name, meta)
    if s >= threshold:
        quarantine(name, f"score {s} >= {threshold}")
        print(f"{name} -> QUARANTINED (score={s:.2f})")
    else:
        print(f"{name} -> BENIGN (score={s:.2f})")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("names", nargs="+", help="package names to evaluate")
    p.add_argument("--threshold", type=float, default=0.6)
    args = p.parse_args()
    for n in args.names:
        process(n, args.threshold)


if __name__ == "__main__":
    main()
