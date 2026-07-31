#!/usr/bin/env python3
"""
PackagePolice - Model Training + SHAP Explainability
========================================================
Trains XGBoost (primary), Logistic Regression + Random Forest (sanity-
check baselines), evaluates all three, then runs SHAP on the XGBoost
model for explainability.

WON'T PRODUCE MEANINGFUL RESULTS UNTIL data/dataset.csv CONTAINS BOTH
LABELS. This script is built and tested against synthetic dummy data to
prove the code is correct - the actual model quality is meaningless
until it's run on your real collected dataset.

USAGE:
    python3 scripts/03_modeling/train_model.py

Reads:
    data/dataset.csv               (from universal_collect.py)
    data/semantic_features.csv     (optional - from extract_semantic_embeddings.py)
Writes:
    models/xgboost_model.json
    models/baseline_models.joblib
    models/shap_summary.png
    models/shap_waterfall_example.png
    Prints a metrics comparison table to stdout.
"""

import json
import os
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")  # no display available on a server/VM
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (precision_score, recall_score, f1_score,
                              roc_auc_score, confusion_matrix, classification_report)

import xgboost as xgb
import shap

warnings.filterwarnings("ignore")

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DATASET_CSV = REPO_ROOT / "data" / "dataset.csv"
SEMANTIC_CSV = REPO_ROOT / "data" / "semantic_features.csv"
MODELS_DIR = REPO_ROOT / "models"

# Columns that are identifiers, free text, or already-redundant with a
# numeric column elsewhere in the schema - not usable as ML features.
# (Verified against universal_collect.py's actual field population, not
# guessed from column names alone - see the accompanying guide for why
# each one is excluded.)
DROP_COLUMNS = [
    "package_name", "version", "sha256", "data_source", "author_name",
    "author_email", "description", "homepage", "repository_url",
    "keywords", "maintainers", "license", "top_dependencies",
    "dependency_tree_file", "github_repo_owner", "suspicious_keywords_found",
    "install_script_preview", "file_extensions", "risky_function_calls_detail",
    "first_release_date", "last_release_date",  # replaced by derived *_days features below
]

BOOL_COLUMNS = [
    "extraction_skipped", "metadata_completeness", "training_eligible",
    "has_description", "has_license", "has_homepage",
    "has_malicious_dependency", "maintainer_email_domain_checked",
    "is_disposable_email", "has_github_repo", "maintainer_other_packages_unchecked",
    "has_install_script", "flag_internet_call", "flag_system_command",
    "flag_download_run", "flag_sensitive_read", "has_setup_py",
    "has_pyproject_toml", "has_setup_cfg", "has_python_code",
    "has_javascript_code", "js_ast_parse_success",
]


def to_bool_int(series):
    return series.astype(str).str.strip().str.lower().map(
        {"true": 1, "false": 0, "1": 1, "0": 0, "yes": 1, "no": 0}
    )


def engineer_date_features(df):
    now = pd.Timestamp.now(tz="UTC")
    for src, out in [("first_release_date", "package_age_days"),
                     ("last_release_date", "days_since_last_release")]:
        parsed = pd.to_datetime(df[src], errors="coerce", utc=True)
        df[out] = (now - parsed).dt.days
    return df


def load_and_prepare():
    df = pd.read_csv(DATASET_CSV, dtype=str)
    print(f"Loaded {len(df)} rows, {len(df.columns)} columns from {DATASET_CSV}")

    if SEMANTIC_CSV.exists():
        sem = pd.read_csv(SEMANTIC_CSV, dtype=str)
        df = df.merge(sem, on=["ecosystem", "package_name", "version"], how="left")
        print(f"Joined semantic features -> {len(df.columns)} columns")
    else:
        print("No semantic_features.csv found - proceeding without signal 5's real embeddings "
              "(only the AST-analysis columns already in dataset.csv).")

    # NOTE: filtering out training_eligible == False here, not by deleting
    # rows from dataset.csv itself - keeps the raw collected data intact
    # while protecting the model from the leakage risk those rows carry.
    before = len(df)
    if "training_eligible" in df.columns:
        df = df[to_bool_int(df["training_eligible"]) == 1].copy()
        print(f"Filtered to training_eligible rows: {before} -> {len(df)}")

    df = engineer_date_features(df)

    y = df["label"].str.strip().str.lower().map({"benign": 0, "malicious": 1})
    if y.isna().any():
        bad = df.loc[y.isna(), "label"].unique()
        raise ValueError(f"Unrecognized label value(s): {bad} - expected only 'benign'/'malicious'")

    is_npm = (df["ecosystem"].str.strip().str.lower() == "npm").astype(int)

    X = df.drop(columns=[c for c in DROP_COLUMNS if c in df.columns] + ["label", "ecosystem"],
                errors="ignore")

    for col in BOOL_COLUMNS:
        if col in X.columns:
            X[col] = to_bool_int(X[col])

    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    X["is_npm"] = is_npm.values

    return X, y


def evaluate(name, model, X_test, y_test):
    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]
    print(f"\n--- {name} ---")
    print(f"Precision: {precision_score(y_test, preds, zero_division=0):.3f}")
    print(f"Recall:    {recall_score(y_test, preds, zero_division=0):.3f}")
    print(f"F1:        {f1_score(y_test, preds, zero_division=0):.3f}")
    try:
        print(f"ROC-AUC:   {roc_auc_score(y_test, probs):.3f}")
    except ValueError:
        print("ROC-AUC:   n/a (only one class present in y_test)")
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(y_test, preds))


def main():
    if not DATASET_CSV.exists():
        print(f"No dataset at {DATASET_CSV} - run universal_collect.py first.")
        return

    X, y = load_and_prepare()
    print(f"\nFinal feature matrix: {X.shape[0]} rows x {X.shape[1]} columns")
    print(f"Label distribution: benign={sum(y == 0)}, malicious={sum(y == 1)}")

    if y.nunique() < 2:
        print("\n[STOP] Only one label present in the data. Can't train a classifier yet - "
              "you need both benign AND malicious rows in data/dataset.csv first.")
        return

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    print(f"\nTrain: {len(X_train)} rows ({sum(y_train==1)} malicious) | "
          f"Test: {len(X_test)} rows ({sum(y_test==1)} malicious)")

    # ---- XGBoost (primary) ----
    # scale_pos_weight compensates for class imbalance so recall on the
    # minority (malicious) class isn't sacrificed for overall accuracy -
    # matches the project's recall-first evaluation principle.
    neg, pos = sum(y_train == 0), sum(y_train == 1)
    scale_pos_weight = neg / pos if pos > 0 else 1.0
    xgb_model = xgb.XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.05,
        scale_pos_weight=scale_pos_weight, eval_metric="logloss",
        random_state=42,
    )
    xgb_model.fit(X_train, y_train)
    evaluate("XGBoost (primary)", xgb_model, X_test, y_test)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_recall = cross_val_score(xgb_model, X_train, y_train, cv=cv, scoring="recall")
    print(f"5-fold CV recall on training set: {cv_recall.mean():.3f} +/- {cv_recall.std():.3f}")

    # ---- Baselines (need imputation - unlike XGBoost, these don't
    # handle NaN natively) ----
    lr_pipeline = Pipeline([
        ("impute", SimpleImputer(strategy="median")),
        ("scale", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)),
    ])
    lr_pipeline.fit(X_train, y_train)
    evaluate("Logistic Regression (baseline)", lr_pipeline, X_test, y_test)

    rf_pipeline = Pipeline([
        ("impute", SimpleImputer(strategy="median")),
        ("clf", RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42)),
    ])
    rf_pipeline.fit(X_train, y_train)
    evaluate("Random Forest (baseline)", rf_pipeline, X_test, y_test)

    # ---- SHAP on the primary model ----
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    explainer = shap.TreeExplainer(xgb_model)
    shap_values = explainer(X_test)

    plt.figure()
    shap.summary_plot(shap_values, X_test, plot_type="bar", show=False)
    plt.tight_layout()
    plt.savefig(MODELS_DIR / "shap_summary.png", dpi=150)
    plt.close()
    print(f"\nSaved SHAP global summary -> {MODELS_DIR / 'shap_summary.png'}")

    malicious_idx = np.where(y_test.values == 1)[0]
    example_idx = int(malicious_idx[0]) if len(malicious_idx) else 0
    plt.figure()
    shap.plots.waterfall(shap_values[example_idx], show=False)
    plt.tight_layout()
    plt.savefig(MODELS_DIR / "shap_waterfall_example.png", dpi=150)
    plt.close()
    print(f"Saved SHAP per-example waterfall -> {MODELS_DIR / 'shap_waterfall_example.png'}")

    # ---- Save everything ----
    xgb_model.save_model(str(MODELS_DIR / "xgboost_model.json"))
    joblib.dump({"logistic_regression": lr_pipeline, "random_forest": rf_pipeline},
                MODELS_DIR / "baseline_models.joblib")
    with open(MODELS_DIR / "feature_columns.json", "w") as f:
        json.dump(list(X.columns), f, indent=2)
    print(f"\nModels saved to {MODELS_DIR}/")


if __name__ == "__main__":
    main()
