"""Tests for model training and evaluation."""
import tempfile
from pathlib import Path

import numpy as np
import pytest

from app.ml.dataset_generator import generate_synthetic_dataset
from app.ml.preprocessor import DataPreprocessor
from app.ml.trainer import train_and_evaluate, _compute_metrics


@pytest.fixture(scope="module")
def trained_artifacts():
    """Train once and reuse across tests in this module."""
    df = generate_synthetic_dataset(n_normal=200, n_suspicious=100)
    p = DataPreprocessor()
    cleaned = p.clean(df)
    X_train, X_test, y_train, y_test = p.fit_transform(cleaned)

    with tempfile.TemporaryDirectory() as tmpdir:
        best_model, best_name, all_metrics = train_and_evaluate(
            X_train, X_test, y_train, y_test,
            output_dir=Path(tmpdir),
        )
        yield {
            "model": best_model,
            "name": best_name,
            "metrics": all_metrics,
            "X_test": X_test,
            "y_test": y_test,
            "tmpdir": tmpdir,
        }


def test_training_returns_model(trained_artifacts):
    assert trained_artifacts["model"] is not None


def test_best_model_name_is_string(trained_artifacts):
    name = trained_artifacts["name"]
    assert isinstance(name, str)
    assert name in ["RandomForest", "LogisticRegression", "DecisionTree"]


def test_all_three_models_evaluated(trained_artifacts):
    models = trained_artifacts["metrics"]["model_metrics"]
    assert "RandomForest" in models
    assert "LogisticRegression" in models
    assert "DecisionTree" in models


def test_metrics_keys_present(trained_artifacts):
    best = trained_artifacts["name"]
    bm = trained_artifacts["metrics"]["model_metrics"][best]
    for key in ["accuracy", "f1_suspicious", "recall_suspicious",
                "precision_suspicious", "false_positive_rate",
                "true_positives", "false_positives"]:
        assert key in bm, f"Missing key: {key}"


def test_metrics_in_valid_range(trained_artifacts):
    best = trained_artifacts["name"]
    bm = trained_artifacts["metrics"]["model_metrics"][best]
    assert 0.0 <= bm["accuracy"] <= 1.0
    assert 0.0 <= bm["f1_suspicious"] <= 1.0
    assert 0.0 <= bm["recall_suspicious"] <= 1.0
    assert 0.0 <= bm["false_positive_rate"] <= 1.0


def test_model_can_predict(trained_artifacts):
    model = trained_artifacts["model"]
    X_test = trained_artifacts["X_test"]
    preds = model.predict(X_test)
    assert len(preds) == len(X_test)
    assert set(preds).issubset({0, 1})


def test_compute_metrics_single_class_warning():
    """Single-class test set should return a warning key."""
    y_true = np.array([0, 0, 0, 0])
    y_pred = np.array([0, 0, 0, 0])
    import warnings
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        metrics = _compute_metrics(y_true, y_pred, "test_model")
    assert "warning" in metrics


def test_confusion_matrix_shape(trained_artifacts):
    best = trained_artifacts["name"]
    bm = trained_artifacts["metrics"]["model_metrics"][best]
    cm = bm["confusion_matrix"]
    assert len(cm) == 2
    assert len(cm[0]) == 2
