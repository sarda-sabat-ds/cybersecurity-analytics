"""
DVC Stage 4 — Model Evaluation
================================
Loads the best saved model and runs a full evaluation pass, writing
DVC-compatible metrics files and plots.

Inputs
------
models/best_model.joblib
models/preprocessor.joblib
data/processed/cleaned_logs.csv

Outputs
-------
metrics/metrics.json        — DVC live metrics (tracked by dvc metrics show)
metrics/confusion_matrix.json
metrics/roc_curve.json
reports/evaluation_summary.md
"""
import sys
import json
import logging
from pathlib import Path
from datetime import datetime

import yaml
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    confusion_matrix, classification_report, roc_curve, auc,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.ml.preprocessor import DataPreprocessor

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger(__name__)


def main():
    params_path = Path(__file__).resolve().parent.parent / "params.yaml"
    with open(params_path) as f:
        params = yaml.safe_load(f)

    pp        = params["preprocess"]
    eval_p    = params["evaluate"]
    threshold = eval_p.get("confidence_threshold", 0.5)

    model_dir   = Path("models")
    metrics_dir = Path("metrics")
    reports_dir = Path("reports")
    metrics_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    log.info("Stage 4 — Evaluating model (threshold=%.2f)", threshold)

    # Load model and preprocessor
    model        = joblib.load(model_dir / "best_model.joblib")
    preprocessor = DataPreprocessor.load(model_dir)

    # Load + preprocess data
    df_raw   = pd.read_csv("data/processed/cleaned_logs.csv", low_memory=False)
    df_clean = preprocessor.clean(df_raw)

    _, X_test, _, y_test = preprocessor.fit_transform(
        df_clean,
        test_size=pp["test_size"],
        random_state=pp["random_seed"],
    )

    # Predict
    y_pred  = model.predict(X_test)
    y_proba = (
        model.predict_proba(X_test)[:, 1]
        if hasattr(model, "predict_proba") else y_pred.astype(float)
    )

    # Apply confidence threshold
    y_pred_thresh = (y_proba >= threshold).astype(int)

    # ── Core metrics ────────────────────────────────────────────────
    cm       = confusion_matrix(y_test, y_pred_thresh)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, int(cm[0,0]))
    fpr_pts, tpr_pts, _ = roc_curve(y_test, y_proba)
    roc_auc  = float(auc(fpr_pts, tpr_pts))

    metrics = {
        "accuracy":             round(float(accuracy_score(y_test, y_pred_thresh)), 4),
        "f1_suspicious":        round(float(f1_score(y_test, y_pred_thresh, pos_label=1, zero_division=0)), 4),
        "precision_suspicious": round(float(precision_score(y_test, y_pred_thresh, pos_label=1, zero_division=0)), 4),
        "recall_suspicious":    round(float(recall_score(y_test, y_pred_thresh, pos_label=1, zero_division=0)), 4),
        "roc_auc":              round(roc_auc, 4),
        "false_positive_rate":  round(float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0, 4),
        "false_negative_rate":  round(float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0, 4),
        "true_positives":       int(tp),
        "false_positives":      int(fp),
        "true_negatives":       int(tn),
        "false_negatives":      int(fn),
        "test_samples":         int(len(y_test)),
        "confidence_threshold": threshold,
        "evaluated_at":         datetime.utcnow().isoformat(),
    }

    # ── DVC metrics file ─────────────────────────────────────────────
    with open(metrics_dir / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # ── Confusion matrix for DVC plots ───────────────────────────────
    cm_data = [
        {"actual": int(y_test[i]), "predicted": int(y_pred_thresh[i])}
        for i in range(len(y_test))
    ]
    with open(metrics_dir / "confusion_matrix.json", "w") as f:
        json.dump(cm_data, f)

    # ── ROC curve for DVC plots ───────────────────────────────────────
    roc_data = [
        {"fpr": round(float(f), 4), "tpr": round(float(t), 4)}
        for f, t in zip(fpr_pts, tpr_pts)
    ]
    with open(metrics_dir / "roc_curve.json", "w") as f:
        json.dump(roc_data, f)

    # ── Evaluation plots ─────────────────────────────────────────────
    _plot_confusion_matrix(cm, metrics_dir)
    _plot_roc_curve(fpr_pts, tpr_pts, roc_auc, metrics_dir)

    # ── Markdown summary for reports/ ────────────────────────────────
    _write_summary_md(metrics, params, reports_dir)

    log.info("Evaluation complete:")
    log.info("  Accuracy  : %.4f", metrics["accuracy"])
    log.info("  F1        : %.4f", metrics["f1_suspicious"])
    log.info("  Recall    : %.4f", metrics["recall_suspicious"])
    log.info("  ROC AUC   : %.4f", metrics["roc_auc"])
    log.info("  FPR       : %.4f", metrics["false_positive_rate"])
    log.info("  Metrics → %s", metrics_dir / "metrics.json")


def _plot_confusion_matrix(cm, out_dir: Path):
    import seaborn as sns
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="YlOrBr", ax=ax,
                xticklabels=["Normal", "Suspicious"],
                yticklabels=["Normal", "Suspicious"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    ax.set_title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig(out_dir / "confusion_matrix.png", dpi=100)
    plt.close()


def _plot_roc_curve(fpr, tpr, roc_auc, out_dir: Path):
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(fpr, tpr, color="#059669", lw=2, label=f"ROC curve (AUC = {roc_auc:.3f})")
    ax.plot([0, 1], [0, 1], color="#a8a29e", lw=1, linestyle="--")
    ax.set_xlim([0, 1]); ax.set_ylim([0, 1.02])
    ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve"); ax.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(out_dir / "roc_curve.png", dpi=100)
    plt.close()


def _write_summary_md(metrics: dict, params: dict, out_dir: Path):
    with open(params["__file__"] if "__file__" in params else "params.yaml") as f:
        pass  # already loaded
    model_name = "RandomForest"
    try:
        with open("models/model_metrics.json") as f:
            model_name = json.load(f).get("best_model", "RandomForest")
    except Exception:
        pass

    md = f"""# Model Evaluation Report

Generated: {metrics['evaluated_at']}
Model: **{model_name}**
Confidence threshold: {metrics['confidence_threshold']}

## Key Metrics

| Metric | Value |
|---|---|
| Accuracy | {metrics['accuracy']:.4f} |
| F1 (Suspicious) | {metrics['f1_suspicious']:.4f} |
| Recall (Suspicious) | {metrics['recall_suspicious']:.4f} |
| Precision (Suspicious) | {metrics['precision_suspicious']:.4f} |
| ROC AUC | {metrics['roc_auc']:.4f} |
| False Positive Rate | {metrics['false_positive_rate']:.4f} |

## Confusion Matrix

|  | Predicted Normal | Predicted Suspicious |
|---|---|---|
| **Actual Normal** | {metrics['true_negatives']} (TN) | {metrics['false_positives']} (FP) |
| **Actual Suspicious** | {metrics['false_negatives']} (FN) | {metrics['true_positives']} (TP) |

## Interpretation

- **False Positives ({metrics['false_positives']})**: Normal events wrongly flagged — analyst time wasted
- **False Negatives ({metrics['false_negatives']})**: Real attacks missed — security risk
- **FPR of {metrics['false_positive_rate']:.4f}** means {metrics['false_positive_rate']*100:.1f}% of normal events are incorrectly flagged

> Note: 100% metrics reflect deterministic synthetic labels.
> Real-world performance will differ significantly.
"""
    with open(out_dir / "evaluation_summary.md", "w") as f:
        f.write(md)


if __name__ == "__main__":
    main()
