"""
DVC Stage 2 — Data Preprocessing
==================================
Loads the raw synthetic dataset, validates schema, cleans it, and saves
the cleaned version plus preprocessing artifacts.

Inputs
------
data/synthetic/synthetic_logs.csv

Outputs
-------
data/processed/cleaned_logs.csv
data/processed/preprocessing_report.json
models/preprocessor.joblib
models/label_encoder.joblib
models/preprocessor_meta.json
"""
import sys
import json
import logging
from pathlib import Path
from datetime import datetime

import yaml
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.ml.preprocessor import DataPreprocessor

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger(__name__)


def main():
    params_path = Path(__file__).resolve().parent.parent / "params.yaml"
    with open(params_path) as f:
        params = yaml.safe_load(f)

    pp = params["preprocess"]
    test_size    = pp["test_size"]
    random_seed  = pp["random_seed"]
    scale        = pp["scale_features"]

    raw_path  = Path("data/synthetic/synthetic_logs.csv")
    proc_dir  = Path("data/processed")
    model_dir = Path("models")
    proc_dir.mkdir(parents=True, exist_ok=True)
    model_dir.mkdir(parents=True, exist_ok=True)

    log.info("Stage 2 — Preprocessing: test_size=%.2f scale=%s", test_size, scale)

    preprocessor = DataPreprocessor(scale_features=scale)

    # Load + validate
    df_raw = preprocessor.load_and_validate(raw_path)
    log.info("Loaded raw dataset: %d rows", len(df_raw))

    # Clean
    df_clean = preprocessor.clean(df_raw)
    log.info("After cleaning: %d rows", len(df_clean))

    # Fit + transform (save split sizes but don't store arrays — trainer does that)
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(
        df_clean, test_size=test_size, random_state=random_seed
    )

    # Save cleaned CSV
    clean_path = proc_dir / "cleaned_logs.csv"
    df_clean.to_csv(clean_path, index=False)

    # Save preprocessor artifacts
    preprocessor.save(model_dir)

    # Write preprocessing report
    label_counts = df_clean["label"].value_counts().to_dict()
    report = {
        "stage":              "preprocess",
        "processed_at":       datetime.utcnow().isoformat(),
        "raw_rows":           len(df_raw),
        "cleaned_rows":       len(df_clean),
        "removed_rows":       len(df_raw) - len(df_clean),
        "test_size":          test_size,
        "random_seed":        random_seed,
        "scale_features":     scale,
        "train_samples":      int(len(X_train)),
        "test_samples":       int(len(X_test)),
        "n_features":         int(X_train.shape[1]),
        "label_distribution": label_counts,
        "class_balance_pct":  {
            k: round(v / len(df_clean) * 100, 2)
            for k, v in label_counts.items()
        },
    }
    with open(proc_dir / "preprocessing_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    log.info("Preprocessing complete — train=%d test=%d features=%d",
             len(X_train), len(X_test), X_train.shape[1])
    log.info("Cleaned dataset → %s", clean_path)
    log.info("Preprocessor artifacts → %s", model_dir)


if __name__ == "__main__":
    main()
