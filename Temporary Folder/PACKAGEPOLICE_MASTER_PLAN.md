# PackagePolice — Master Dataset & Model Build Plan

**Status: you are at zero.** Ubuntu is installed, VS Code is installed, VS Code is signed into GitHub. Nothing else exists yet. This document takes you from there to a trained, SHAP-explainable model on a 5,000+ row dataset, in order, with no steps skipped.

**How to use this document:** follow the parts in order. Each part has a short "why" before the "how" — read the why once, then just execute the how every time you repeat that step. Every script named here has been written and tested (details on what was and wasn't testable are noted where relevant, so you know exactly how much to trust each piece before running it on real data).

---

## Part 0 — The Decisions (read this once, it governs everything below)

| Decision | Value | Why |
|---|---|---|
| Total dataset size | **5,200 rows** | 5,000 minimum + ~4% buffer, because some collection attempts always fail (dead links, deleted packages, network timeouts) and you don't want to land at 4,950 after cleaning. |
| Benign : Malicious split | **3,900 : 1,300 (3:1, 75%/25%)** | See justification below. |
| Ecosystem balance | **Even npm/PyPI split within each label** (650 malicious npm / 650 malicious PyPI, 1,950 benign npm / 1,950 benign PyPI) | See justification below. |
| Package version | **Always pinned to an exact version**, never "latest" | A claim about a package's risk is a claim about one specific version. "Latest" silently drifts if the package publishes a new release next month — your dataset would stop being reproducible. |
| Train/test split | **80/20, stratified by label** | See justification below. |
| Model | **XGBoost (primary)**, Logistic Regression + Random Forest (baselines) | Already your team's established choice — this plan just operationalizes it. |
| Explainability | **SHAP TreeExplainer** on the XGBoost model | Tree-native, exact (not an approximation), fast. |

### Why 3:1 benign:malicious, not 1:1 or heavily imbalanced?

Three real options exist, and your own literature review already tried all three:
- **1:1 balanced** (like DySec's ~7,127 malicious / 7,144 benign) makes the model's reported numbers look better than it would perform in the real world, because the real world is nowhere near 1:1 — it's overwhelmingly benign.
- **Extremely imbalanced, matching the real world** (like SAC'25's 138 malicious out of 5,331, ~2.6%) is the most "honest" to reality, but it starves the model of malicious examples to learn from, which hurt that paper's malicious-class recall.
- **Moderately imbalanced, ~1:3 to 1:4** (like OSCAR's 500:1500 and Ea4mp's 3,404:10,000) is the middle ground: enough malicious examples for the model to actually learn the pattern, while still being meaningfully imbalanced enough that `scale_pos_weight`/recall-focused tuning is a real, defensible part of your methodology rather than a formality on an artificially balanced set.

1,300 malicious samples is comfortably achievable (the OSV malicious-package aggregator alone has on the order of 200,000+ npm+PyPI malicious records available, per what we found researching this — you are not data-starved on the malicious side).

### Why force an even npm/PyPI split, when 2026's real attack landscape is npm-heavy?

Recent industry tracking shows npm now makes up the large majority of newly discovered open-source malware, with PyPI's share falling after that registry rolled out mandatory 2FA and trusted publishing. If you sampled malicious packages proportionally to that real-world skew, your dataset would end up mostly-npm-malicious, and the model could learn "ecosystem == npm" as a shortcut for "probably malicious" — a shortcut that would fall apart the moment it's asked to judge a malicious PyPI package, and one that inflates your reported numbers without the model actually having learned the real signal patterns. Forcing balance across ecosystems keeps `is_npm` from becoming a proxy label. Document this as a deliberate methodological choice in your report — it's a legitimate thing to defend under examiner questioning, not something to hide.

### Why 80/20 train/test, plus 5-fold CV?

80/20 is the standard convention and, at 1,300 malicious rows, still leaves ~260 malicious examples in the test set — enough for a stable precision/recall/F1 estimate (a test set with only 10-20 malicious examples would make those numbers noisy and easy for an examiner to poke holes in). Stratification keeps that same 3:1 ratio in both the train and test splits, so the test set isn't accidentally skewed. On top of the single 80/20 split, running 5-fold stratified cross-validation on the training portion gives you a second, more robust number (mean ± std recall) to report alongside the single test-set score — this is what "rigorous" evaluation means to an examiner, versus a single lucky/unlucky split.

---

## Part 1 — Environment Setup

**Why:** every teammate needs the exact same tool versions, or the same script will behave subtly differently on different machines (e.g. someone missing `esprima` gets weaker JavaScript analysis and nobody notices the column looks the same but means less).

1. Confirm Python 3.10+ is available in your Ubuntu environment:
   ```bash
   python3 --version
   ```
2. Clone the repo (VS Code is already signed into GitHub, so **Source Control panel → Clone Repository** works directly — paste `https://github.com/NabiulIslamNabil/PackagePolice.git` when prompted, no manual token typing needed anymore).
3. Open the cloned folder in VS Code.
4. Open a terminal inside VS Code (**Terminal → New Terminal**) and create the folder structure:
   ```bash
   mkdir -p scripts/01_data_collection scripts/03_modeling data models
   ```
5. Get the following files into `scripts/01_data_collection/` (attached to this plan): `requirements.txt`, `universal_collect.py`, `pull_malicious_candidates.py`, `pull_benign_candidates.py`, `build_master_list.py`, `extract_semantic_embeddings.py`. Put `train_model.py` in `scripts/03_modeling/`.

   **How to actually get the files in:** download them from this chat to your host machine, then either (a) drag-and-drop upload them into the GitHub web UI at the right path and commit, then `git pull` inside your Ubuntu environment, or (b) if you're working directly on the Ubuntu machine with normal clipboard access, just save them straight into the folders VS Code has open. Use whichever your actual clipboard/host-guest setup allows — the point is the files end up at those exact paths.

6. Install dependencies:
   ```bash
   pip3 install -r scripts/01_data_collection/requirements.txt --break-system-packages
   pip3 install scikit-learn xgboost shap matplotlib joblib pandas --break-system-packages
   ```
7. Create `.gitignore` in the repo root:
   ```
   quarantine/
   raw/
   logs/
   embeddings/
   models/
   __pycache__/
   *.pyc
   ```
   `data/*.csv` and `data/master_list.csv` are **not** ignored — those are the shared deliverables everyone pulls and pushes.
8. Set your GitHub token as an environment variable (raises the GitHub API limit from 60/hour to 5,000/hour — without this, collection stalls for minutes at a time waiting out rate limits):
   ```bash
   export GITHUB_TOKEN=your_token_here
   ```
   Create one at github.com → Settings → Developer settings → Personal access tokens → generate with `repo` scope.

---

## Part 2 — Repository Structure (what goes where, and why)

```
PackagePolice/
├── scripts/
│   ├── 01_data_collection/
│   │   ├── requirements.txt
│   │   ├── pull_malicious_candidates.py   # builds malicious half of master_list.csv
│   │   ├── pull_benign_candidates.py      # builds benign half of master_list.csv
│   │   ├── build_master_list.py           # merges the two into one shuffled list
│   │   ├── universal_collect.py           # THE feature extractor - all 5 signals
│   │   └── extract_semantic_embeddings.py # real CodeBERT step, run after collection
│   └── 03_modeling/
│       └── train_model.py                 # cleaning + XGBoost/LR/RF + SHAP
├── data/
│   ├── master_list.csv          # committed - the "what to collect" list
│   ├── dataset.csv              # committed - the actual feature table (66 cols)
│   └── semantic_features.csv    # committed - the 2-3 semantic scalar columns
├── models/          # gitignored - regenerate by re-running train_model.py
├── quarantine/       # gitignored - downloaded package archives, ephemeral
├── raw/               # gitignored - saved metadata JSON, dependency trees, OSV cache
├── logs/               # gitignored - collection logs, esprima failure logs
└── embeddings/    # gitignored - raw 768-dim .npy vectors per package
```

**Why this split of committed vs. gitignored:** `data/*.csv` are small (a few MB at most), human-readable, diffable, and are the actual research artifact — commit them. Everything else is either large, regeneratable from the CSVs plus a re-run, or (in `quarantine/`'s case) literal downloaded package code that should never sit in a public GitHub history.

---

## Part 3 — Building the Master Package List

**Why this order:** you need to know *which* 5,200 packages you're collecting before you extract features from any of them. This step produces `data/master_list.csv` — nothing here downloads full packages yet, it only resolves names and pins versions.

### 3a. Malicious candidates

```bash
cd ~/PackagePolice
python3 scripts/01_data_collection/pull_malicious_candidates.py \
    --npm-count 650 --pypi-count 650 \
    --output data/malicious_candidates.csv
```

What this does: downloads OSV.dev's official bulk export for each ecosystem (`osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` — this is Google's own documented mechanism, an aggregator that already folds in DataDog's malicious-packages dataset, the PyPI malware registry, Backstabber's Knife Collection, and GitHub's malware advisories), filters for entries whose ID starts with `MAL-` (OSV's convention for confirmed malicious-package reports, as opposed to ordinary CVE-style bugs), and randomly samples the requested count per ecosystem with an exact affected version pinned from each record.

**Honest limitation:** the JSON-parsing logic in this script was tested against a mock file built to match OSV's real, documented schema, and passed. The actual live download could not be tested from the sandbox this was built in, because that network doesn't allow reaching Google Cloud Storage. Run it for real here, and sanity-check the printed counts (`Found N distinct malicious pairs`) before trusting it blindly — if N looks suspiciously low or zero, something about the download or zip format changed and needs a look.

### 3b. Benign candidates

```bash
python3 scripts/01_data_collection/pull_benign_candidates.py \
    --npm-count 1950 --pypi-count 1950 \
    --output data/benign_candidates.csv
```

This one **was** tested live, successfully, end to end. PyPI candidates come from `hugovk/top-pypi-packages` (a live, monthly-updated real-download-count ranking of the top 15,000 PyPI packages). npm candidates come from npm's own registry search API, queried across ~30 deliberately unrelated search terms (`react`, `express`, `crypto`, `test`, `build`, etc.) rather than one single query — a single query biases the pool toward whatever that term matches best, and a wide spread of terms gives a much more representative cross-section of the ecosystem. Candidates are randomly sampled from the *whole* pool, not just the single most popular packages — if every benign example were a massively famous, massively healthy package, the model could learn "very popular = benign" as a shortcut that falls apart on any real but less-famous benign package.

### 3c. Merge into the final list

```bash
python3 scripts/01_data_collection/build_master_list.py
```

Produces `data/master_list.csv` (shuffled, deduplicated, ~5,200 rows). Commit this file — it's the shared "what to collect" contract for the whole team.

---

## Part 4 — Running the Universal Collector (the 5 signals)

**Why one script for all 5 signals, run by everyone:** a shared schema is worthless if five people extract features five slightly different ways. One script, one schema, committed once, run by everyone against their own slice of `master_list.csv`.

### What the 5 signals actually are in this script

| Signal | Column prefix / examples | What it captures |
|---|---|---|
| 1. Metadata | `meta`-adjacent: `version_count`, `package_size_kb`, `has_license`, `npm_download_count`, `is_disposable_email`, `maintainer_other_packages_count` | Package-level facts and maintainer-trust signals (including a disposable-email check most teams don't think to add) |
| 2. Dependency tree | `direct_dependency_count`, `total_dependency_count`, `max_dependency_depth`, `has_malicious_dependency` | Real recursive tree walk to depth 3, including whether any transitive dependency is itself on the malicious list — supply-chain risk propagation, not just a direct-dependency count |
| 3. Maintainer reputation | `repo_stars`, `repo_forks`, `github_contributors_count`, `maintainer_github_account_age_days`, `is_disposable_email` | GitHub-derived trust signals, rate-limit-aware so it doesn't hammer the API |
| 4. Install scripts | `has_install_script`, `suspicious_keyword_count`, `flag_internet_call`, `flag_system_command`, `flag_download_run`, `flag_sensitive_read` | Real AST-based analysis (not regex) — correctly distinguishes a dangerous call sitting at the top level of `setup.py` (executes on install) from the same call inside a function (doesn't) |
| 5. Code analysis (AST-based, not embeddings) | `source_file_count`, `total_lines_of_code`, `risky_function_calls_total`, `obfuscation_indicators` | AST-level risky-call counting and obfuscation flags. **This is not a semantic embedding** — real CodeBERT-based semantic similarity is Part 5, a separate step. |

### Run it, in batches

```bash
python3 scripts/01_data_collection/universal_collect.py \
    --list data/master_list.csv \
    --limit 400
```

Run this exact command repeatedly (once a session, across as many days as you need). Every run:
- Skips every `(ecosystem, package_name, version)` already in `data/dataset.csv`
- Processes up to 400 *new* ones (or however many `--limit` says)
- Is safe to interrupt (Ctrl+C, or a network blip) — the next run resumes exactly where it left off, nothing is lost or reprocessed

**Timing expectation, from real testing:** individual packages took anywhere from 10 to 60+ seconds depending on how deep the dependency tree goes and GitHub's rate-limit state. Time your first 30-40 package run and multiply for your real estimate on a 400-package batch — don't assume it'll be instant. With `GITHUB_TOKEN` set (Part 1, step 8), this is dramatically faster than without it.

### If more than one teammate is collecting in parallel

Don't have everyone write to the same `data/dataset.csv` filename at the same time — you'll get git merge conflicts on a CSV. Instead, each person collects to their own file:
```bash
python3 scripts/01_data_collection/universal_collect.py --list data/master_list.csv --limit 400 --output data/dataset_<yourname>.csv
```
(Requires overriding `DATASET_CSV` per-run — simplest is to temporarily edit that one path constant, or ask for a `--output` flag to be added if this becomes the actual workflow.) Merge everyone's files at the end the same way `build_master_list.py` merges candidate lists — dedupe by `(ecosystem, package_name, version)`, concatenate, done.

---

## Part 5 — Semantic Analysis (run after Part 4, separately)

**Why separate, and why after:** this step needs `torch`+`transformers` (a multi-GB dependency) and reuses the source code Part 4 already downloaded — it doesn't re-download anything. Keeping it as its own script means Part 4 stays fast and dependency-light for everyone, and this heavier step only needs to run once per collected batch, not per teammate.

```bash
pip3 install torch transformers --break-system-packages
python3 scripts/01_data_collection/extract_semantic_embeddings.py
```

What happens: for every package already in `data/dataset.csv`, it finds that package's already-extracted source in `quarantine/<ecosystem>/<label>/<name>-<version>/extracted/`, runs up to 30 of its largest source files through CodeBERT, mean-pools them into one 768-dimensional vector per package, and saves that raw vector to `embeddings/<key>.npy`. It then computes a benign centroid (and, once you have malicious data, a malicious centroid too) and writes just two numbers per package — `sem_sim_to_benign`, `sem_sim_to_malicious` (cosine similarity to each centroid) — to `data/semantic_features.csv`.

**Why only 2 numbers, and not the 768 raw dimensions, in the shared table:** 768 raw columns would dwarf the other 4 signals (which together are only ~46 usable features) and make SHAP output uninterpretable ("dimension 342 contributed +0.3" means nothing to an examiner). Compressing to a similarity score keeps the semantic signal genuinely usable in a tree-based model, and mirrors what your own literature review's "1+1>2 / Ea4mp" paper does — combining a BERT branch's *output* with a metadata branch, not concatenating raw features.

`train_model.py` (Part 7) automatically joins this file to `data/dataset.csv` if it exists — no manual merging needed.

**Honest limitation:** this script's logic was fully verified (installed torch+transformers for real, confirmed it reaches exactly the model-download step correctly, independently tested the cosine-similarity/centroid math with dummy vectors) but the actual CodeBERT model download couldn't be tested end-to-end, because Hugging Face's servers aren't reachable from the sandbox this was built in. It will work from a normal internet connection — just expect the first run to take a few minutes downloading the ~500MB model, and don't kill it if it looks idle.

---

## Part 6 — Data Cleaning

**Why this isn't a separate script:** cleaning is embedded directly inside `train_model.py`'s `load_and_prepare()` function, on your team's own stated preference for consolidated scripts over scattered ones. Here's exactly what it does, and why:

- **Filters to `training_eligible == True` rows only** — protects against the data-leakage risk your teammate's script already flags for packages recovered via local-archive fallback with incomplete metadata. This filters *in the training script*, not by deleting rows from `dataset.csv` itself, so the raw collected data stays intact for inspection.
- **Derives `package_age_days` and `days_since_last_release`** from the raw date strings — a genuinely useful feature that wasn't a direct numeric column in the collection schema, computed here instead of re-plumbing the collector.
- **Drops identifier/free-text columns** (`package_name`, `sha256`, `description`, `top_dependencies`, `install_script_preview`, etc.) — verified against the actual code that populates them, not guessed from column names alone, so a column like `obfuscation_indicators` (a real numeric counter) is correctly kept while `file_extensions` (a comma-joined string) is correctly dropped.
- **Converts boolean-like text columns** (`"True"`/`"False"` strings from the CSV) to real 0/1.
- **Leaves genuine missing values as NaN** for XGBoost (which handles them natively by learning a default split direction) rather than filling with 0, which would falsely imply "confirmed zero" instead of "not measured" — e.g. `repo_stars` is blank when a GitHub repo couldn't be resolved, not actually zero stars.

---

## Part 7 — Model Training + SHAP

```bash
python3 scripts/03_modeling/train_model.py
```

This single script:
1. Loads and cleans `data/dataset.csv`, joins `data/semantic_features.csv` if present (Part 6)
2. Splits 80/20, stratified by label (Part 0's decision)
3. Trains **XGBoost** with `scale_pos_weight` set from the actual train-split class ratio, so recall on the malicious class isn't sacrificed for overall accuracy — your team's established recall-first principle, operationalized as an actual hyperparameter rather than a slogan
4. Runs 5-fold stratified cross-validation on the training set, reporting mean ± std recall as a robustness check alongside the single test-set number
5. Trains **Logistic Regression** and **Random Forest** baselines, each through a proper `SimpleImputer` + (for LR) `StandardScaler` pipeline — unlike XGBoost, neither of these handles missing values natively, so skipping this step would silently crash or corrupt them
6. Prints precision/recall/F1/ROC-AUC/confusion matrix for all three models
7. Runs `shap.TreeExplainer` on the trained XGBoost model, saves a global feature-importance bar chart to `models/shap_summary.png` and a per-package waterfall explanation (for one malicious example) to `models/shap_waterfall_example.png`
8. Saves the trained XGBoost model, both baseline pipelines, and the exact feature-column list used, to `models/`

**This was fully tested end-to-end** — including SHAP plot generation — against a synthetic 400-row dataset built to match the real 66-column schema exactly, with realistic feature distributions (planted differences between benign/malicious on the columns that should differ). It ran cleanly with zero crashes and produced real, valid PNG plots. The 100% accuracy that test run showed is expected and means nothing — that data was synthetic and deliberately separable. **Do not expect anywhere near that on real data**; the point of that test was proving the code is correct, not previewing your results.

---

## Part 8 — Team Git Workflow (recap)

1. Whoever collects, `git add data/*.csv`, commit, push.
2. Everyone else `git pull` before running anything, so `data/master_list.csv`'s already-collected rows are respected by the resume-safe skip logic.
3. Never commit `quarantine/`, `raw/`, `logs/`, `embeddings/`, or `models/` — they're gitignored for a reason (size, and in `quarantine/`'s case, literal downloaded package code).
4. If two people collected to separate output files in parallel (Part 4's note), merge before the modeling step — `train_model.py` expects one `data/dataset.csv`.

---

## Appendix — Script Reference

| Script | Run in | Tested how |
|---|---|---|
| `pull_malicious_candidates.py` | Part 3a | Parsing logic verified against a mock file matching OSV's real schema; live download untested (network-restricted sandbox) |
| `pull_benign_candidates.py` | Part 3b | Fully tested live against real PyPI + npm sources |
| `build_master_list.py` | Part 3c | Fully tested |
| `universal_collect.py` | Part 4 | Fully tested live against real npm/PyPI/GitHub, including resume-safety across an interrupted run and multi-batch `--limit` behavior |
| `extract_semantic_embeddings.py` | Part 5 | Logic and math fully verified; live model download untested (network-restricted sandbox) |
| `train_model.py` | Part 7 | Fully tested end-to-end on synthetic data matching the real schema, including SHAP plot generation |

## Appendix — If something looks wrong

- **`maint_error` / blank GitHub columns**: you hit the unauthenticated 60/hour GitHub limit. Set `GITHUB_TOKEN` (Part 1, step 8) and re-run — resume-safety means you lose nothing.
- **A package times out mid-collection**: just re-run the same command. Resume-safe.
- **`pull_malicious_candidates.py` returns 0 or very few records**: OSV's export format or URL may have changed since this was written — check `https://google.github.io/osv.dev/data/` for the current documented path.
- **Training script says "only one label present"**: you haven't collected any malicious rows yet, or they didn't survive the `training_eligible` filter. Check `data/dataset.csv`'s `label` column directly.
