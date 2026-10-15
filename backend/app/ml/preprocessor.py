"""
Data preprocessing pipeline for cybersecurity log data.

Handles loading, validation, cleaning, feature engineering, encoding,
scaling, and train/test splitting. Saves preprocessing artifacts for
reproducible inference.
"""
import json
import logging
import warnings
from pathlib import Path
from typing import Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder

logger = logging.getLogger(__name__)

# Required columns — the pipeline validates these are present
REQUIRED_COLUMNS = [
    "event_type", "severity", "failed_login_count",
    "request_count", "port", "label",
]

# Optional columns — used if present
OPTIONAL_COLUMNS = [
    "source_ip", "destination_ip", "affected_asset", "timestamp", "log_id",
]

# Feature columns used for ML (no target label, no IDs, no leakage)
CATEGORICAL_FEATURES = ["event_type", "severity"]
NUMERICAL_FEATURES = ["failed_login_count", "request_count", "port"]

TARGET_COLUMN = "label"


class DataPreprocessor:
    """
    End-to-end preprocessing pipeline for security log datasets.

    The pipeline:
    1. Validates column presence.
    2. Removes duplicates.
    3. Handles missing values.
    4. Validates data types.
    5. Encodes categorical features (OneHotEncoder for tree models,
       optional StandardScaler for linear models).
    6. Splits into train/test with stratification.
    7. Saves artifacts (scaler, encoder, feature names) for inference.
    """

    def __init__(self, scale_features: bool = False):
        """
        Parameters
        ----------
        scale_features : bool
            If True, applies StandardScaler to numerical features.
            Useful for Logistic Regression; not needed for tree models.
        """
        self.scale_features = scale_features
        self.feature_names_: list = []
        self.preprocessor_: Optional[ColumnTransformer] = None
        self.label_encoder_: Optional[LabelEncoder] = None
        self._is_fitted = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_and_validate(self, path: Path) -> pd.DataFrame:
        """Load CSV and validate schema."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Dataset not found: {path}")

        df = pd.read_csv(path, low_memory=False)
        logger.info("Loaded dataset: %d rows, %d columns from %s", len(df), len(df.columns), path)

        missing_required = [c for c in REQUIRED_COLUMNS if c not in df.columns]
        if missing_required:
            raise ValueError(
                f"Dataset missing required columns: {missing_required}. "
                f"Found: {list(df.columns)}"
            )

        return df

    def clean(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean the dataset: duplicates, missing values, type coercion."""
        original_len = len(df)

        # Remove duplicate rows (keep first)
        df = df.drop_duplicates()
        if len(df) < original_len:
            logger.info("Removed %d duplicate rows", original_len - len(df))

        # Drop rows with missing target label
        df = df.dropna(subset=[TARGET_COLUMN])

        # Coerce numeric columns — invalid values become NaN then are filled
        for col in NUMERICAL_FEATURES:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce")
                median_val = df[col].median()
                n_missing = df[col].isna().sum()
                if n_missing > 0:
                    logger.warning("Column '%s': %d missing values — filled with median %.1f", col, n_missing, median_val)
                df[col] = df[col].fillna(median_val if not np.isnan(median_val) else 0)
                df[col] = df[col].clip(lower=0)  # counts can't be negative

        # Fill missing categorical features with a placeholder
        for col in CATEGORICAL_FEATURES:
            if col in df.columns:
                n_missing = df[col].isna().sum()
                if n_missing > 0:
                    logger.warning("Column '%s': %d missing values — filled with 'unknown'", col, n_missing)
                df[col] = df[col].fillna("unknown").astype(str).str.lower().str.strip()

        # Validate label values
        valid_labels = {"normal", "suspicious"}
        unknown_labels = set(df[TARGET_COLUMN].unique()) - valid_labels
        if unknown_labels:
            logger.warning("Unexpected label values found: %s — rows will be dropped", unknown_labels)
            df = df[df[TARGET_COLUMN].isin(valid_labels)]

        if len(df) == 0:
            raise ValueError("Dataset is empty after cleaning.")

        # Class balance check
        label_counts = df[TARGET_COLUMN].value_counts()
        logger.info("Label distribution after cleaning:\n%s", label_counts.to_string())

        if len(label_counts) < 2:
            warnings.warn(
                "WARNING: Only one class present in the dataset. "
                "Meaningful ML evaluation is not possible. "
                "Please use a dataset with both 'normal' and 'suspicious' labels.",
                UserWarning,
                stacklevel=2,
            )

        return df.reset_index(drop=True)

    def fit_transform(
        self,
        df: pd.DataFrame,
        test_size: float = 0.2,
        random_state: int = 42,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Fit preprocessor on training data and transform both splits.

        Returns X_train, X_test, y_train, y_test as numpy arrays.
        Stratified split is used when both classes are present.
        """
        # Separate features and target — no leakage
        X_raw = df[CATEGORICAL_FEATURES + NUMERICAL_FEATURES].copy()
        y_raw = df[TARGET_COLUMN].copy()

        # Encode labels: normal=0, suspicious=1
        self.label_encoder_ = LabelEncoder()
        y = self.label_encoder_.fit_transform(y_raw)
        logger.info("Label encoding: %s", dict(zip(self.label_encoder_.classes_, self.label_encoder_.transform(self.label_encoder_.classes_))))

        # Build sklearn ColumnTransformer
        categorical_transformer = OneHotEncoder(
            handle_unknown="ignore", sparse_output=False
        )
        numerical_transformer = (
            StandardScaler() if self.scale_features else "passthrough"
        )

        self.preprocessor_ = ColumnTransformer(
            transformers=[
                ("cat", categorical_transformer, CATEGORICAL_FEATURES),
                ("num", numerical_transformer, NUMERICAL_FEATURES),
            ],
            remainder="drop",
        )

        # Stratified split when both classes are available
        n_classes = len(np.unique(y))
        use_stratify = n_classes > 1
        if not use_stratify:
            logger.warning("Only one class present — skipping stratification.")

        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            X_raw, y,
            test_size=test_size,
            random_state=random_state,
            stratify=y if use_stratify else None,
        )

        # Fit on train, transform both
        X_train = self.preprocessor_.fit_transform(X_train_raw)
        X_test = self.preprocessor_.transform(X_test_raw)

        # Store feature names for reporting
        cat_names = list(
            self.preprocessor_.named_transformers_["cat"].get_feature_names_out(CATEGORICAL_FEATURES)
        )
        self.feature_names_ = cat_names + NUMERICAL_FEATURES
        self._is_fitted = True

        logger.info(
            "Train/test split: %d train, %d test | Features: %d",
            len(X_train), len(X_test), X_train.shape[1],
        )
        return X_train, X_test, y_train, y_test

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform new data using the fitted preprocessor (for inference)."""
        if not self._is_fitted:
            raise RuntimeError("Preprocessor must be fitted before calling transform().")

        # Ensure required columns present, fill missing ones
        for col in CATEGORICAL_FEATURES + NUMERICAL_FEATURES:
            if col not in df.columns:
                logger.warning("Missing column '%s' — filling with default", col)
                if col in CATEGORICAL_FEATURES:
                    df[col] = "unknown"
                else:
                    df[col] = 0

        df = df.copy()
        for col in CATEGORICAL_FEATURES:
            df[col] = df[col].fillna("unknown").astype(str).str.lower().str.strip()
        for col in NUMERICAL_FEATURES:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).clip(lower=0)

        X = df[CATEGORICAL_FEATURES + NUMERICAL_FEATURES]
        return self.preprocessor_.transform(X)

    def save(self, output_dir: Path):
        """Save fitted preprocessor artifacts."""
        if not self._is_fitted:
            raise RuntimeError("Preprocessor must be fitted before saving.")
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        joblib.dump(self.preprocessor_, output_dir / "preprocessor.joblib")
        joblib.dump(self.label_encoder_, output_dir / "label_encoder.joblib")

        meta = {
            "categorical_features": CATEGORICAL_FEATURES,
            "numerical_features": NUMERICAL_FEATURES,
            "feature_names": self.feature_names_,
            "scale_features": self.scale_features,
            "label_classes": list(self.label_encoder_.classes_),
        }
        with open(output_dir / "preprocessor_meta.json", "w") as f:
            json.dump(meta, f, indent=2)

        logger.info("Preprocessor artifacts saved to %s", output_dir)

    @classmethod
    def load(cls, artifacts_dir: Path) -> "DataPreprocessor":
        """Load a fitted preprocessor from saved artifacts."""
        artifacts_dir = Path(artifacts_dir)
        instance = cls()
        instance.preprocessor_ = joblib.load(artifacts_dir / "preprocessor.joblib")
        instance.label_encoder_ = joblib.load(artifacts_dir / "label_encoder.joblib")

        with open(artifacts_dir / "preprocessor_meta.json") as f:
            meta = json.load(f)

        instance.feature_names_ = meta["feature_names"]
        instance.scale_features = meta["scale_features"]
        instance._is_fitted = True
        logger.info("Preprocessor loaded from %s", artifacts_dir)
        return instance
