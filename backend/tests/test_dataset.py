"""Tests for dataset generation and loading."""
import pytest
import pandas as pd
from pathlib import Path
import tempfile

from app.ml.dataset_generator import generate_synthetic_dataset


def test_generate_returns_dataframe():
    """Generator returns a non-empty DataFrame with at least n_normal+n_suspicious rows
    (campaigns add extra records, so we check >= base count)."""
    df = generate_synthetic_dataset(n_normal=50, n_suspicious=20, n_campaigns=0)
    assert isinstance(df, pd.DataFrame)
    # With no campaigns exact count equals n_normal + n_suspicious
    assert len(df) == 70


def test_generate_includes_campaign_rows():
    """Campaigns add extra suspicious rows on top of the base counts."""
    df_no_camp  = generate_synthetic_dataset(n_normal=50, n_suspicious=20, n_campaigns=0)
    df_with_camp = generate_synthetic_dataset(n_normal=50, n_suspicious=20, n_campaigns=5)
    assert len(df_with_camp) > len(df_no_camp)


def test_label_distribution():
    """Base normal/suspicious counts are preserved (campaigns may add more suspicious)."""
    df = generate_synthetic_dataset(n_normal=100, n_suspicious=50, n_campaigns=0)
    counts = df["label"].value_counts()
    assert counts["normal"] == 100
    assert counts["suspicious"] == 50


def test_label_distribution_with_campaigns():
    """With campaigns, suspicious count >= n_suspicious, normal stays at n_normal."""
    df = generate_synthetic_dataset(n_normal=100, n_suspicious=50, n_campaigns=3)
    counts = df["label"].value_counts()
    assert counts["normal"] == 100
    assert counts["suspicious"] >= 50


def test_required_columns_present():
    df = generate_synthetic_dataset(n_normal=20, n_suspicious=10, n_campaigns=0)
    required = {"log_id", "timestamp", "source_ip", "destination_ip",
                "event_type", "severity", "failed_login_count",
                "request_count", "port", "affected_asset", "label"}
    assert required.issubset(set(df.columns))


def test_new_columns_present():
    """New extended schema includes username, bytes_transferred, process_name."""
    df = generate_synthetic_dataset(n_normal=20, n_suspicious=10, n_campaigns=0)
    for col in ["username", "bytes_transferred", "process_name", "user_agent"]:
        assert col in df.columns, f"Missing new column: {col}"


def test_save_to_csv():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = Path(tmpdir) / "test_logs.csv"
        df = generate_synthetic_dataset(n_normal=30, n_suspicious=10,
                                         n_campaigns=0, output_path=out)
        assert out.exists()
        df2 = pd.read_csv(out)
        # Exact match when no campaigns
        assert len(df2) == 40


def test_no_missing_labels():
    df = generate_synthetic_dataset(n_normal=50, n_suspicious=20, n_campaigns=2)
    assert df["label"].isna().sum() == 0


def test_only_valid_labels():
    df = generate_synthetic_dataset(n_normal=50, n_suspicious=20, n_campaigns=2)
    assert set(df["label"].unique()).issubset({"normal", "suspicious"})


def test_event_types_are_strings():
    df = generate_synthetic_dataset(n_normal=30, n_suspicious=10, n_campaigns=0)
    assert df["event_type"].apply(lambda x: isinstance(x, str)).all()


def test_reproducible_columns():
    """Column structure is always identical regardless of campaign count."""
    df1 = generate_synthetic_dataset(n_normal=50, n_suspicious=20, n_campaigns=0)
    df2 = generate_synthetic_dataset(n_normal=50, n_suspicious=20, n_campaigns=3)
    assert list(df1.columns) == list(df2.columns)


def test_sorted_by_timestamp():
    """Output is sorted by timestamp ascending."""
    df = generate_synthetic_dataset(n_normal=100, n_suspicious=30, n_campaigns=2)
    ts = pd.to_datetime(df["timestamp"])
    assert ts.is_monotonic_increasing


def test_large_dataset_size():
    """Smoke-test a medium dataset to make sure generation is fast enough."""
    df = generate_synthetic_dataset(n_normal=5_000, n_suspicious=2_000, n_campaigns=20)
    assert len(df) >= 7_000
    assert (df["label"] == "suspicious").sum() >= 2_000
