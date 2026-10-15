"""
ML model training, evaluation, and selection pipeline.

Trains and compares multiple scikit-learn classifiers on the preprocessed
cybersecurity log dataset. Selects the best model based on documented
evaluation criteria with emphasis on suspicious-event recall.

MODEL SELECTION CRITERIA:
- Primary: F1-score for the 'suspicious' class (class 1)
- Secondary: Recall for the 'suspicious' class (to minimize missed threats)
- Tertiary: False-positive rate (to reduce alert fatigue)
- Overall accuracy used as a tiebreaker only

We do NOT assume Random Forest is always best. The winner is determined
by actual measured metrics on a held-out test set.
"""
import json
import logging
import warnings
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

import joblib
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server use
import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

logger = logging.getLogger(__name__)

# Candidate models — same interface, comparable splits
CANDIDATE_MODELS = {
    "RandomForest": RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    ),
    "LogisticRegression": LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42,
        solver="lbfgs",
    ),
    "DecisionTree": DecisionTreeClassifier(
        max_depth=8,
        min_samples_leaf=10,
        class_weight="balanced",
        random_state=42,
    ),
}


def _compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, model_name: str) -> Dict[str, Any]:
    """Compute all evaluation metrics for a single model."""
    if len(np.unique(y_true)) < 2:
        warnings.warn(
            f"Model '{model_name}': Test set has only one class. "
            "Metrics are misleading — skipping.",
            UserWarning,
            stacklevel=2,
        )
        return {"warning": "Only one class in test set. Metrics are unreliable."}

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, int(cm[0, 0]))

    report = classification_report(y_true, y_pred, target_names=["normal", "suspicious"], output_dict=True)

    metrics = {
        "model_name": model_name,
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision_suspicious": round(float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "recall_suspicious": round(float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "f1_suspicious": round(float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "f1_macro": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0, 4),
        "false_negative_rate": round(float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0, 4),
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
    }
    return metrics


def _score_for_selection(metrics: Dict[str, Any]) -> float:
    """
    Composite selection score.
    Primary weight on F1 for suspicious class, penalise high FPR.
    """
    if "warning" in metrics:
        return -1.0
    f1 = metrics.get("f1_suspicious", 0.0)
    recall = metrics.get("recall_suspicious", 0.0)
    fpr = metrics.get("false_positive_rate", 1.0)
    # Weighted composite: F1 carries 50%, recall 30%, FPR penalty 20%
    return 0.5 * f1 + 0.3 * recall - 0.2 * fpr


def train_and_evaluate(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    output_dir: Path,
    scale_features: bool = False,
) -> Tuple[Any, str, Dict[str, Any]]:
    """
    Train all candidate models, evaluate them, select the best, and save.

    Returns
    -------
    best_model : fitted sklearn estimator
    best_model_name : str
    all_metrics : dict mapping model names to their metric dicts
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # When scale_features=True, LogisticRegression benefits; trees don't care
    models_to_train = CANDIDATE_MODELS.copy()
    if not scale_features:
        # LR can still work without scaling but might underperform slightly
        logger.info("scale_features=False — LogisticRegression trained without scaling (may underperform vs tree models)")

    all_metrics: Dict[str, Any] = {}
    trained_models: Dict[str, Any] = {}

    logger.info("=" * 60)
    logger.info("TRAINING AND EVALUATING %d CANDIDATE MODELS", len(models_to_train))
    logger.info("=" * 60)

    for name, model in models_to_train.items():
        logger.info("Training: %s ...", name)
        try:
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            metrics = _compute_metrics(y_test, y_pred, name)
            all_metrics[name] = metrics
            trained_models[name] = model

            logger.info(
                "%s — Accuracy: %.4f | F1 (suspicious): %.4f | "
                "Recall (suspicious): %.4f | FPR: %.4f",
                name,
                metrics.get("accuracy", 0),
                metrics.get("f1_suspicious", 0),
                metrics.get("recall_suspicious", 0),
                metrics.get("false_positive_rate", 0),
            )
        except Exception as e:
            logger.error("Failed to train %s: %s", name, str(e))
            all_metrics[name] = {"error": str(e)}

    # Select best model
    scores = {n: _score_for_selection(m) for n, m in all_metrics.items()}
    best_model_name = max(scores, key=lambda k: scores[k])
    best_model = trained_models[best_model_name]

    logger.info("=" * 60)
    logger.info("MODEL SELECTION SCORES: %s", {k: round(v, 4) for k, v in scores.items()})
    logger.info("SELECTED MODEL: %s (selection score: %.4f)", best_model_name, scores[best_model_name])
    logger.info("SELECTION CRITERIA: 0.5*F1_suspicious + 0.3*Recall_suspicious - 0.2*FPR")
    logger.info("=" * 60)

    # Save best model
    model_path = output_dir / "best_model.joblib"
    joblib.dump(best_model, model_path)
    logger.info("Best model saved to %s", model_path)

    # Save all metrics
    metrics_payload = {
        "best_model": best_model_name,
        "selection_scores": {k: round(v, 4) for k, v in scores.items()},
        "selection_criteria": "0.5*F1_suspicious + 0.3*Recall_suspicious - 0.2*FPR",
        "trained_at": datetime.utcnow().isoformat(),
        "model_metrics": all_metrics,
    }
    with open(output_dir / "model_metrics.json", "w") as f:
        json.dump(metrics_payload, f, indent=2)

    # Generate evaluation charts
    _plot_confusion_matrices(all_metrics, output_dir)
    _plot_metrics_comparison(all_metrics, output_dir)

    return best_model, best_model_name, metrics_payload


def _plot_confusion_matrices(all_metrics: Dict, output_dir: Path):
    """Save confusion matrix plots for each model."""
    import seaborn as sns
    valid = {n: m for n, m in all_metrics.items() if "confusion_matrix" in m}
    if not valid:
        return

    fig, axes = plt.subplots(1, len(valid), figsize=(5 * len(valid), 4))
    if len(valid) == 1:
        axes = [axes]

    for ax, (name, metrics) in zip(axes, valid.items()):
        cm = np.array(metrics["confusion_matrix"])
        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues", ax=ax,
            xticklabels=["Normal", "Suspicious"],
            yticklabels=["Normal", "Suspicious"],
        )
        ax.set_title(f"{name}\nAcc={metrics['accuracy']:.3f}")
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")

    plt.tight_layout()
    plt.savefig(output_dir / "confusion_matrices.png", dpi=100, bbox_inches="tight")
    plt.close()
    logger.info("Confusion matrix plots saved")


def _plot_metrics_comparison(all_metrics: Dict, output_dir: Path):
    """Save bar chart comparing key metrics across models."""
    valid = {n: m for n, m in all_metrics.items() if "accuracy" in m}
    if not valid:
        return

    names = list(valid.keys())
    metrics_keys = ["accuracy", "f1_suspicious", "recall_suspicious", "precision_suspicious"]
    labels = ["Accuracy", "F1 (Susp.)", "Recall (Susp.)", "Precision (Susp.)"]
    colors = ["#4C72B0", "#DD8452", "#55A868", "#C44E52"]

    x = np.arange(len(names))
    width = 0.18
    fig, ax = plt.subplots(figsize=(10, 5))

    for i, (key, label, color) in enumerate(zip(metrics_keys, labels, colors)):
        values = [valid[n].get(key, 0) for n in names]
        ax.bar(x + i * width, values, width, label=label, color=color, alpha=0.85)

    ax.set_xlabel("Model")
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison — Key Evaluation Metrics")
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(names)
    ax.set_ylim(0, 1.1)
    ax.legend(loc="lower right")
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_dir / "model_comparison.png", dpi=100, bbox_inches="tight")
    plt.close()
    logger.info("Model comparison chart saved")
