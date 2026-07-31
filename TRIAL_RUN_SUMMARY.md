# PackagePolice Trial Run Summary (30-Package Verification)

## Objective
Verify that the full PackagePolice pipeline works end-to-end on a small trial set before scaling to thousands of packages.

## Trial Scope Used
- Target master list size: 30
- Label plan: 22 benign, 8 malicious
- Ecosystem target split: npm and pypi represented in both labels

## What Was Completed

### 1) Project and Dependency Validation
- Project structure was organized according to the master plan.
- Required dependencies were installed and verified.
- CPU-friendly setup was used for PyTorch/Transformers to avoid GPU CUDA download issues.

### 2) Candidate Generation
- Malicious candidates generated from OSV export.
- Benign candidates generated successfully.
- Master list built successfully.

### 3) Master List Creation
- Final trial master list created at 30 rows.
- Distribution at master list stage:
  - benign: 22
  - malicious: 8
  - npm benign/malicious: 11/4
  - pypi benign/malicious: 11/4

### 4) Universal Collection Run
- Collector executed with trial limit.
- Because some malicious versions are removed/yanked in live registries, not all 30 could be collected.
- Final collected dataset rows: 23
  - benign: 18
  - malicious: 5

### 5) Feature Schema Verification
- Dataset contains 66 columns.
- Core columns and all 5 signal families were verified present.

### 6) Semantic Embedding Extraction
- CodeBERT model downloaded and embedding script ran.
- semantic_features produced successfully.
- Some rows had no semantic output due to no usable source files or timing/order of collection updates.

### 7) Model Training and Explainability
- train_model.py completed successfully.
- XGBoost, Logistic Regression, and Random Forest all trained.
- SHAP summary and waterfall plots generated successfully.

## Warnings/Issues Observed During Trial

1. Some malicious package versions were not downloadable from live npm/pypi.
- Effect: fewer malicious rows collected than planned.
- Mitigation used: larger malicious pool and reachability filtering.

2. Some package-level extraction failures occurred (null metadata structure errors).
- Effect: package skipped in dataset row writing.
- Mitigation: continue run with buffer/oversampling strategy.

3. GitHub rate-limit waiting was observed.
- Effect: slower collection for some rows.
- Mitigation: use GITHUB_TOKEN in collection sessions.

4. JS parser (esprima) parse failures on specific files.
- Effect: logged as failures; pipeline still continued.

## Final Output Status

All required pipeline artifacts for trial verification are present:
- data/master_list.csv: present
- data/dataset.csv: present
- data/semantic_features.csv: present
- models/xgboost_model.json: present
- models/baseline_models.joblib: present
- models/feature_columns.json: present
- models/shap_summary.png: present
- models/shap_waterfall_example.png: present

## Where To See Your Work Outputs

### Core Data Outputs
- data/master_list.csv
- data/dataset.csv
- data/semantic_features.csv

### Model Outputs
- models/xgboost_model.json
- models/baseline_models.joblib
- models/feature_columns.json

### Explainability Outputs
- models/shap_summary.png
- models/shap_waterfall_example.png

### Collection/Parsing Logs
- logs/collection_log.csv
- logs/esprima_parse_failures.csv

### Intermediate Embeddings
- embeddings/

## Quick Commands To Inspect Outputs

```bash
# Show key files
ls -lh data models logs embeddings | cat

# Preview dataset shape and labels
python3 - <<'PY'
import pandas as pd

ds = pd.read_csv('data/dataset.csv')
print('rows:', len(ds), 'cols:', len(ds.columns))
print(ds['label'].value_counts(dropna=False))
PY

# Preview semantic file
python3 - <<'PY'
import pandas as pd
sf = pd.read_csv('data/semantic_features.csv')
print('rows:', len(sf), 'cols:', len(sf.columns))
print(sf.head(5).to_string(index=False))
PY
```

## Conclusion
Trial objective achieved: the full PackagePolice pipeline was successfully validated end-to-end on a small batch, including data collection, feature generation, semantic stage, model training, and SHAP outputs.
