"""
train_model.py — End-to-end ML training script.

Usage:
    cd backend
    python scripts/train_model.py                       # default large dataset
    python scripts/train_model.py --csv path/to/file.csv
    python scripts/train_model.py --normal 30000 --suspicious 10000 --campaigns 200
"""
import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings
from app.ml.dataset_generator import generate_synthetic_dataset
from app.ml.preprocessor import DataPreprocessor
from app.ml.trainer import train_and_evaluate

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Train cybersecurity ML models")
    parser.add_argument("--csv",        type=str, default=None)
    parser.add_argument("--normal",     type=int, default=30_000)
    parser.add_argument("--suspicious", type=int, default=10_000)
    parser.add_argument("--campaigns",  type=int, default=200)
    parser.add_argument("--scale",      action="store_true")
    args = parser.parse_args()

    settings.ensure_directories()
    models_dir     = settings.models_path
    synthetic_path = settings.synthetic_data_dir / "synthetic_logs.csv"
    processed_path = settings.processed_data_dir / "cleaned_logs.csv"

    preprocessor = DataPreprocessor(scale_features=args.scale)

    if args.csv:
        logger.info("Loading custom dataset: %s", args.csv)
        df = preprocessor.load_and_validate(Path(args.csv))
    else:
        logger.info(
            "Generating synthetic dataset: normal=%d suspicious=%d campaigns=%d",
            args.normal, args.suspicious, args.campaigns,
        )
        df = generate_synthetic_dataset(
            n_normal=args.normal,
            n_suspicious=args.suspicious,
            n_campaigns=args.campaigns,
            output_path=synthetic_path,
        )

    df_clean = preprocessor.clean(df)
    df_clean.to_csv(processed_path, index=False)
    logger.info("Cleaned dataset: %d rows → %s", len(df_clean), processed_path)

    X_train, X_test, y_train, y_test = preprocessor.fit_transform(df_clean)

    best_model, best_name, all_metrics = train_and_evaluate(
        X_train, X_test, y_train, y_test,
        output_dir=models_dir,
        scale_features=args.scale,
    )
    preprocessor.save(models_dir)

    print("\n" + "=" * 62)
    print("  TRAINING COMPLETE")
    print("=" * 62)
    print(f"  Dataset  : {len(df_clean):,} records")
    label_counts = df_clean["label"].value_counts()
    for lbl, cnt in label_counts.items():
        print(f"             {lbl}: {cnt:,} ({100*cnt/len(df_clean):.1f}%)")
    print(f"  Model    : {best_name}")
    print(f"  Saved to : {models_dir}")
    print()
    for name, metrics in all_metrics.get("model_metrics", {}).items():
        if "accuracy" in metrics:
            print(f"  [{name}]")
            print(f"    Accuracy              : {metrics['accuracy']:.4f}")
            print(f"    F1 (suspicious)       : {metrics['f1_suspicious']:.4f}")
            print(f"    Recall (suspicious)   : {metrics['recall_suspicious']:.4f}")
            print(f"    Precision (suspicious): {metrics['precision_suspicious']:.4f}")
            print(f"    False Positive Rate   : {metrics['false_positive_rate']:.4f}")
            print()
    print("=" * 62)


if __name__ == "__main__":
    main()
