"""Tests for data preprocessing pipeline."""
import pytest
import numpy as np
import pandas as pd
import tempfile
from pathlib import Path

from app.ml.preprocessor import DataPreprocessor


@pytest.fixture
def full_df():
    """Minimal but valid dataset with both classes."""
    rows = []
    for i in range(40):
        rows.append({
            "log_id": f"id{i}", "timestamp": "2024-01-01T00:00:00",
            "source_ip": "192.168.1.1", "destination_ip": "10.0.0.1",
            "event_type": "login_success" if i % 2 == 0 else "brute_force",
            "severity": "low" if i % 2 == 0 else "high",
            "failed_login_count": 0 if i % 2 == 0 else 15,
            "request_count": 5 if i % 2 == 0 else 30,
            "port": 443, "affected_asset": "web-server-01",
            "label": "normal" if i % 2 == 0 else "suspicious",
        })
    return pd.DataFrame(rows)


def test_clean_removes_duplicates(full_df):
    duped = pd.concat([full_df, full_df], ignore_index=True)
    p = DataPreprocessor()
    cleaned = p.clean(duped)
    assert len(cleaned) == len(full_df)


def test_clean_fills_missing_numerics(full_df):
    df = full_df.copy()
    df.loc[0, "failed_login_count"] = None
    p = DataPreprocessor()
    cleaned = p.clean(df)
    assert cleaned["failed_login_count"].isna().sum() == 0


def test_clean_fills_missing_categoricals(full_df):
    df = full_df.copy()
    df.loc[0, "event_type"] = None
    p = DataPreprocessor()
    cleaned = p.clean(df)
    assert cleaned["event_type"].isna().sum() == 0
    assert cleaned.loc[0, "event_type"] == "unknown"


def test_clean_drops_unknown_labels(full_df):
    df = full_df.copy()
    df.loc[0, "label"] = "invalid_label"
    p = DataPreprocessor()
    cleaned = p.clean(df)
    assert "invalid_label" not in cleaned["label"].values


def test_fit_transform_shapes(full_df):
    p = DataPreprocessor()
    cleaned = p.clean(full_df)
    X_train, X_test, y_train, y_test = p.fit_transform(cleaned)
    # 80/20 split of 40 = 32/8
    assert len(X_train) == 32
    assert len(X_test) == 8
    assert len(y_train) == 32
    assert len(y_test) == 8


def test_fit_transform_produces_numpy(full_df):
    p = DataPreprocessor()
    cleaned = p.clean(full_df)
    X_train, X_test, y_train, y_test = p.fit_transform(cleaned)
    assert isinstance(X_train, np.ndarray)
    assert isinstance(y_train, np.ndarray)


def test_save_and_load_preprocessor(full_df):
    with tempfile.TemporaryDirectory() as tmpdir:
        p = DataPreprocessor()
        cleaned = p.clean(full_df)
        p.fit_transform(cleaned)
        p.save(Path(tmpdir))

        loaded = DataPreprocessor.load(Path(tmpdir))
        assert loaded._is_fitted
        assert loaded.feature_names_


def test_transform_on_new_data(full_df):
    p = DataPreprocessor()
    cleaned = p.clean(full_df)
    p.fit_transform(cleaned)

    new_record = pd.DataFrame([{
        "event_type": "port_scan", "severity": "medium",
        "failed_login_count": 100, "request_count": 500, "port": 80,
    }])
    X_new = p.transform(new_record)
    assert X_new.shape[0] == 1


def test_load_and_validate_missing_column(full_df):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "bad.csv"
        df_bad = full_df.drop(columns=["event_type"])
        df_bad.to_csv(path, index=False)
        p = DataPreprocessor()
        with pytest.raises(ValueError, match="missing required columns"):
            p.load_and_validate(path)
