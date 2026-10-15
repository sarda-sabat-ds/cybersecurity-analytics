"""
DVC Stage 3 — Model Training
==============================
Loads the cleaned dataset and preprocessor artifacts, trains all three
candidate models, selects the best, saves artifacts and evaluation results.

Inputs
------
data/processed/cleaned_logs.csv
models/preprocessor.joblib
models/label_encoder.joblib
models/preprocessor_meta.json

Outputs
-------
models/best_model.joblib
models/model_metrics.json
models/confusion_matrices.png
models/model_comparison.png
models/training_report.json
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
from app.ml.trainer import train_and_evaluate

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger(__name__)


def main():
    params_path = Path(__file__).resolve().parent.parent / "params.yaml"
    with open(params_path) as f:
        params = yaml.safe_load(f)

    pp    = params["preprocess"]
    train = params["train"]

    clean_path = Path("data/processed/cleaned_logs.csv")
    model_dir  = Path("models")
    model_dir.mkdir(parents=True, exist_ok=True)

    log.info("Stage 3 — Training models from: %s", clean_path)

    # Load cleaned data
    df = pd.read_csv(clean_path, low_memory=False)
    log.info("Loaded cleaned dataset: %d rows", len(df))

    # Load fitted preprocessor (from stage 2)
    preprocessor = DataPreprocessor.load(model_dir)
    log.info("Preprocessor loaded — features: %s", preprocessor.feature_names_)

    # Re-split with the same seed as preprocessing stage
    X_train, X_test, y_train, y_test = preprocessor.fit_transform(
        preprocessor.clean(df),
        test_size=pp["test_size"],
        random_state=pp["random_seed"],
    )
    log.info("Train=%d  Test=%d  Features=%d", len(X_train), len(X_test), X_train.shape[1])

    # Train and evaluate all models
    best_model, best_name, all_metrics = train_and_evaluate(
        X_train, X_test, y_train, y_test,
        output_dir=model_dir,
        scale_features=pp["scale_features"],
    )

    # Re-save preprocessor (fit_transform called again above)
    preprocessor.save(model_dir)

    # Write training report (human-readable summary)
    bm = all_metrics["model_metrics"].get(best_name, {})
    report = {
        "stage":              "train",
        "trained_at":         datetime.utcnow().isoformat(),
        "dataset_rows":       len(df),
        "train_samples":      int(len(X_train)),
        "test_samples":       int(len(X_test)),
        "n_features":         int(X_train.shape[1]),
        "best_model":         best_name,
        "selection_criteria": all_metrics["selection_criteria"],
        "selection_scores":   all_metrics["selection_scores"],
        "best_model_metrics": {
            "accuracy":              bm.get("accuracy"),
            "f1_suspicious":         bm.get("f1_suspicious"),
            "recall_suspicious":     bm.get("recall_suspicious"),
            "precision_suspicious":  bm.get("precision_suspicious"),
            "false_positive_rate":   bm.get("false_positive_rate"),
            "false_positives":       bm.get("false_positives"),
            "false_negatives":       bm.get("false_negatives"),
            "true_positives":        bm.get("true_positives"),
            "true_negatives":        bm.get("true_negatives"),
        },
        "all_models_summary": {
            name: {
                "accuracy":      m.get("accuracy"),
                "f1_suspicious": m.get("f1_suspicious"),
                "recall":        m.get("recall_suspicious"),
                "fpr":           m.get("false_positive_rate"),
            }
            for name, m in all_metrics["model_metrics"].items()
            if "accuracy" in m
        },
    }
    with open(model_dir / "training_report.json", "w") as f:
        json.dump(report, f, indent=2)

    log.info("Training complete — best model: %s", best_name)
    log.info("Accuracy=%.4f  F1=%.4f  Recall=%.4f  FPR=%.4f",
             bm.get("accuracy", 0), bm.get("f1_suspicious", 0),
             bm.get("recall_suspicious", 0), bm.get("false_positive_rate", 0))


if __name__ == "__main__":
    main()
