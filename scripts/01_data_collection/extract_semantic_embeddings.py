#!/usr/bin/env python3
"""
PackagePolice - Semantic Embedding Extractor
==============================================
Run this AFTER universal_collect.py, on the same repo. It does NOT
re-download anything - it reuses the source already sitting in
quarantine/<ecosystem>/<label>/<name>-<version>/extracted/ from the
collection step.

What it does:
1. For every package already in data/dataset.csv, load its extracted
   source files and run them through CodeBERT to get 768-dim embeddings.
2. Mean-pool per-file embeddings into one 768-dim vector per package.
3. Save the RAW vectors to embeddings/<ecosystem>_<name>_<version>.npy
   (small - ~3KB per package, fine to keep in the repo).
4. Compute a benign centroid (mean vector of all label=benign packages),
   and a malicious centroid once you have malicious rows.
5. For every package, compute cosine similarity to each centroid, and
   write ONLY those 2-3 scalar numbers per package to
   data/semantic_features.csv, joined at training time on
   (ecosystem, package_name, version) - never flattened into the main
   dataset.csv. See the guide for why.

SETUP (one-time, ~500MB download on first run):
    pip install torch transformers --break-system-packages

USAGE:
    python3 scripts/01_data_collection/extract_semantic_embeddings.py

Re-running is safe: existing .npy files are skipped unless --force is
given, and centroids/similarities are always recomputed fresh (cheap)
since they depend on however many benign/malicious vectors exist so far.
"""

import argparse
import csv
import os
from pathlib import Path

import numpy as np

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
QUARANTINE_ROOT = REPO_ROOT / "quarantine"
DATASET_CSV = REPO_ROOT / "data" / "dataset.csv"
EMBEDDINGS_DIR = REPO_ROOT / "embeddings"
OUTPUT_CSV = REPO_ROOT / "data" / "semantic_features.csv"

MODEL_NAME = "microsoft/codebert-base"
MAX_FILES_PER_PACKAGE = 30       # representative sample, not exhaustive -
                                  # a package with 1000+ files (e.g. lodash)
                                  # would otherwise take hours on CPU
MAX_TOKENS = 512                 # CodeBERT's hard limit per input
SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx"}


def find_extracted_dir(ecosystem, package_name, version, label):
    safe_name = package_name.replace("@", "").replace("/", "-")
    d = QUARANTINE_ROOT / ecosystem / label / f"{safe_name}-{version}" / "extracted"
    return d if d.exists() else None


def pick_source_files(extracted_dir):
    files = []
    for p in extracted_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in SOURCE_EXTENSIONS:
            if "/test" in str(p).lower() or "/tests" in str(p).lower():
                continue
            files.append(p)
    # Bias toward larger files first - short __init__.py-style files carry
    # less semantic signal than the package's actual logic.
    files.sort(key=lambda p: p.stat().st_size, reverse=True)
    return files[:MAX_FILES_PER_PACKAGE]


def embed_package(extracted_dir, tokenizer, model, torch, device):
    files = pick_source_files(extracted_dir)
    if not files:
        return None
    vectors = []
    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if not text.strip():
            continue
        inputs = tokenizer(text, return_tensors="pt", truncation=True,
                            max_length=MAX_TOKENS, padding=False).to(device)
        with torch.no_grad():
            outputs = model(**inputs)
        # Mean-pool token embeddings (excluding nothing extra needed here
        # since there's no padding on a single non-batched input).
        vec = outputs.last_hidden_state.mean(dim=1).squeeze(0).cpu().numpy()
        vectors.append(vec)
    if not vectors:
        return None
    return np.mean(vectors, axis=0)


def cosine_sim(a, b):
    denom = (np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true",
                     help="Recompute embeddings even if a .npy already exists")
    args = ap.parse_args()

    try:
        import torch
        from transformers import AutoTokenizer, AutoModel
    except ImportError:
        print("Missing torch/transformers. Install with:")
        print("  pip install torch transformers --break-system-packages")
        return

    if not DATASET_CSV.exists():
        print(f"No dataset found at {DATASET_CSV} - run universal_collect.py first.")
        return

    EMBEDDINGS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Loading {MODEL_NAME} (first run downloads ~500MB, cached after that)...")
    device = "cuda" if torch.cuda.is_available() else "cpu"
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModel.from_pretrained(MODEL_NAME).to(device)
    model.eval()
    print(f"Model loaded on {device}.")

    with open(DATASET_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print(f"{len(rows)} packages in dataset.")

    # Step 1: embed every package that doesn't already have a .npy
    vectors_by_key = {}
    for i, row in enumerate(rows, 1):
        eco, name, ver, label = row["ecosystem"], row["package_name"], row["version"], row["label"]
        key = f"{eco}_{name.replace('@', '').replace('/', '-')}_{ver}"
        npy_path = EMBEDDINGS_DIR / f"{key}.npy"

        if npy_path.exists() and not args.force:
            vectors_by_key[(eco, name, ver, label)] = np.load(npy_path)
            continue

        extracted_dir = find_extracted_dir(eco, name, ver, label)
        if not extracted_dir:
            print(f"  [{i}/{len(rows)}] {name}=={ver}: no extracted source found (was quarantine/ cleared?), skipping")
            continue

        print(f"  [{i}/{len(rows)}] embedding {name}=={ver} ...")
        vec = embed_package(extracted_dir, tokenizer, model, torch, device)
        if vec is None:
            print(f"    no usable source files, skipping")
            continue
        np.save(npy_path, vec)
        vectors_by_key[(eco, name, ver, label)] = vec

    if not vectors_by_key:
        print("No embeddings computed - nothing to do.")
        return

    # Step 2: centroids
    benign_vecs = [v for (eco, name, ver, label), v in vectors_by_key.items() if label == "benign"]
    malicious_vecs = [v for (eco, name, ver, label), v in vectors_by_key.items() if label == "malicious"]
    benign_centroid = np.mean(benign_vecs, axis=0) if benign_vecs else None
    malicious_centroid = np.mean(malicious_vecs, axis=0) if malicious_vecs else None

    print(f"\nCentroids: benign from {len(benign_vecs)} packages, "
          f"malicious from {len(malicious_vecs)} packages"
          + ("" if malicious_vecs else " (none yet - sem_sim_to_malicious will be blank until you have malicious samples)"))

    # Step 3: similarity features -> separate CSV, joined at training time
    out_rows = []
    for (eco, name, ver, label), vec in vectors_by_key.items():
        out_rows.append({
            "ecosystem": eco,
            "package_name": name,
            "version": ver,
            "sem_sim_to_benign": cosine_sim(vec, benign_centroid) if benign_centroid is not None else "",
            "sem_sim_to_malicious": cosine_sim(vec, malicious_centroid) if malicious_centroid is not None else "",
        })

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ecosystem", "package_name", "version",
                                                "sem_sim_to_benign", "sem_sim_to_malicious"])
        writer.writeheader()
        writer.writerows(out_rows)

    print(f"\nWrote {len(out_rows)} rows to {OUTPUT_CSV}")
    print("Join this to data/dataset.csv on (ecosystem, package_name, version) at training time.")


if __name__ == "__main__":
    main()
