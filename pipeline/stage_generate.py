"""
DVC Stage 1 — Data Generation
==============================
Generates the synthetic cybersecurity log dataset and saves it.
Controlled by params.yaml so changing any parameter invalidates the stage.

Outputs
-------
data/synthetic/synthetic_logs.csv   — raw generated dataset
data/synthetic/generation_meta.json — generation metadata for audit trail
"""
import sys
import json
import logging
from pathlib import Path
from datetime import datetime

import yaml

# Allow import from backend/app
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.ml.dataset_generator import generate_synthetic_dataset

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger(__name__)


def main():
    # Load DVC params
    params_path = Path(__file__).resolve().parent.parent / "params.yaml"
    with open(params_path) as f:
        params = yaml.safe_load(f)

    gen = params["generate"]
    n_normal     = gen["n_normal"]
    n_suspicious = gen["n_suspicious"]
    n_campaigns  = gen["n_campaigns"]
    random_seed  = gen["random_seed"]

    log.info("Stage 1 — Generating dataset: normal=%d suspicious=%d campaigns=%d seed=%d",
             n_normal, n_suspicious, n_campaigns, random_seed)

    out_dir = Path("data/synthetic")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "synthetic_logs.csv"

    import random, numpy as np
    random.seed(random_seed)
    np.random.seed(random_seed)

    df = generate_synthetic_dataset(
        n_normal=n_normal,
        n_suspicious=n_suspicious,
        n_campaigns=n_campaigns,
        output_path=out_path,
    )

    # Write generation metadata
    meta = {
        "stage":         "generate",
        "generated_at":  datetime.utcnow().isoformat(),
        "n_normal":      n_normal,
        "n_suspicious":  n_suspicious,
        "n_campaigns":   n_campaigns,
        "random_seed":   random_seed,
        "total_records": len(df),
        "label_counts":  df["label"].value_counts().to_dict(),
        "output_file":   str(out_path),
        "file_size_mb":  round(out_path.stat().st_size / 1_048_576, 3),
    }
    with open(out_dir / "generation_meta.json", "w") as f:
        json.dump(meta, f, indent=2, default=str)

    log.info("Dataset saved: %d rows → %s (%.2f MB)",
             len(df), out_path, meta["file_size_mb"])


if __name__ == "__main__":
    main()
