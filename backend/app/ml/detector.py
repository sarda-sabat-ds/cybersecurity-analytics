"""
Threat detection engine.

Combines ML model predictions with rule-based heuristics to produce
alerts. ML predictions are treated as indicators, not confirmed attacks.
All detections are labelled as 'suspicious' or 'potential threat' — not
as confirmed incidents.

Detection method transparency:
- 'ml': Flagged only by the ML model
- 'rule': Flagged only by a deterministic rule
- 'combined': Flagged by both ML and rule

Confidence scores are produced via predict_proba when available.
"""
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

from app.ml.preprocessor import DataPreprocessor
from app.config import settings

logger = logging.getLogger(__name__)

# Rule-based thresholds (documented, configurable)
RULE_THRESHOLDS = {
    "brute_force_logins": 5,       # failed_login_count >= this → suspicious
    "port_scan_requests": 50,      # request_count >= this on port_scan event
    "high_request_volume": 200,    # any event with request_count >= this
    "suspicious_event_types": {    # event types always flagged
        "brute_force", "port_scan", "data_exfiltration",
        "privilege_escalation", "malware_detected", "account_lockout",
    },
}

# ML confidence threshold above which we trust the prediction
ML_CONFIDENCE_THRESHOLD = 0.55


class DetectionEngine:
    """Loads saved ML model and preprocessor, runs detection on log records."""

    def __init__(self):
        self.model = None
        self.preprocessor: Optional[DataPreprocessor] = None
        self._model_name: str = "unknown"
        self._loaded = False

    def load(self, models_dir: Optional[Path] = None) -> bool:
        """
        Load the ML model and preprocessor artifacts.
        Returns True if loaded successfully, False otherwise.
        """
        models_dir = Path(models_dir or settings.models_path)
        model_path = models_dir / "best_model.joblib"
        preprocessor_dir = models_dir

        if not model_path.exists():
            logger.warning("No trained model found at %s. Detection will use rules only.", model_path)
            self._loaded = False
            return False

        try:
            self.model = joblib.load(model_path)
            self.preprocessor = DataPreprocessor.load(preprocessor_dir)
            self._loaded = True

            # Read model name from metrics file
            metrics_path = models_dir / "model_metrics.json"
            if metrics_path.exists():
                with open(metrics_path) as f:
                    meta = json.load(f)
                self._model_name = meta.get("best_model", "unknown")

            logger.info("Detection engine loaded: model=%s", self._model_name)
            return True
        except Exception as e:
            logger.error("Failed to load model: %s", e)
            self._loaded = False
            return False

    def detect_batch(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Run detection on a DataFrame of log records.
        Returns a list of alert dictionaries (only for suspicious events).
        """
        alerts = []
        df = df.copy()

        # ML predictions (if model available)
        ml_predictions = None
        ml_probabilities = None

        if self._loaded and self.preprocessor is not None:
            try:
                X = self.preprocessor.transform(df)
                raw_preds = self.model.predict(X)
                ml_predictions = raw_preds

                if hasattr(self.model, "predict_proba"):
                    proba = self.model.predict_proba(X)
                    ml_probabilities = proba[:, 1]  # P(suspicious)
                else:
                    ml_probabilities = raw_preds.astype(float)
            except Exception as e:
                logger.error("ML prediction failed: %s", e)

        for idx, row in df.iterrows():
            ml_pred = None
            ml_conf = None
            rule_triggered = False
            evidence = []
            reasons = []

            # ---- ML prediction ----
            if ml_predictions is not None:
                pos = df.index.get_loc(idx) if idx in df.index else idx
                if isinstance(pos, (int, np.integer)):
                    ml_pred = int(ml_predictions[pos])
                    ml_conf = float(ml_probabilities[pos]) if ml_probabilities is not None else None

            # ---- Rule-based checks ----
            event_type = str(row.get("event_type", "")).lower().strip()
            failed = int(row.get("failed_login_count", 0) or 0)
            req_count = int(row.get("request_count", 0) or 0)

            if event_type in RULE_THRESHOLDS["suspicious_event_types"]:
                rule_triggered = True
                reasons.append(f"Event type '{event_type}' is in the suspicious events list.")
                evidence.append({"rule": "suspicious_event_type", "value": event_type})

            if failed >= RULE_THRESHOLDS["brute_force_logins"]:
                rule_triggered = True
                reasons.append(f"High failed login count: {failed} (threshold: {RULE_THRESHOLDS['brute_force_logins']})")
                evidence.append({"rule": "brute_force_logins", "value": failed})

            if req_count >= RULE_THRESHOLDS["high_request_volume"]:
                rule_triggered = True
                reasons.append(f"Unusually high request count: {req_count}")
                evidence.append({"rule": "high_request_volume", "value": req_count})

            # ---- Decision logic ----
            ml_flags = ml_pred == 1 and (ml_conf is None or ml_conf >= ML_CONFIDENCE_THRESHOLD)

            is_suspicious = ml_flags or rule_triggered
            if not is_suspicious:
                continue

            # Determine detection method
            if ml_flags and rule_triggered:
                method = "combined"
            elif ml_flags:
                method = "ml"
            else:
                method = "rule"

            if ml_flags and not rule_triggered:
                reasons.append(
                    f"ML model ({self._model_name}) predicted suspicious "
                    f"(confidence: {ml_conf:.2f})" if ml_conf else
                    f"ML model ({self._model_name}) predicted suspicious."
                )

            alert = {
                "alert_id": str(uuid.uuid4()),
                "log_id": str(row.get("log_id", f"log-{idx}")),
                "timestamp": str(row.get("timestamp", datetime.utcnow().isoformat())),
                "event_type": event_type,
                "source_ip": str(row.get("source_ip", "")),
                "affected_asset": str(row.get("affected_asset", "")),
                "severity": str(row.get("severity", "medium")).lower(),
                "ml_prediction": "suspicious" if ml_pred == 1 else ("normal" if ml_pred == 0 else "n/a"),
                "confidence_score": round(ml_conf, 4) if ml_conf is not None else None,
                "detection_reason": " | ".join(reasons),
                "evidence": evidence,
                "recommended_action": _get_recommended_action(event_type, failed, req_count),
                "detection_method": method,
            }
            alerts.append(alert)

        logger.info("Detection complete: %d suspicious events from %d records", len(alerts), len(df))
        return alerts

    def detect_single(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run detection on a single log record dict."""
        df = pd.DataFrame([record])
        results = self.detect_batch(df)
        return results[0] if results else None

    @property
    def model_loaded(self) -> bool:
        return self._loaded

    @property
    def model_name(self) -> str:
        return self._model_name


def _get_recommended_action(event_type: str, failed_logins: int, req_count: int) -> str:
    """Return a specific recommended action based on event characteristics."""
    actions = {
        "brute_force": "Block source IP immediately. Review and enforce account lockout policy. Enable MFA on targeted accounts.",
        "port_scan": "Block source IP. Review firewall rules. Investigate whether the scan preceded other attack activity.",
        "data_exfiltration": "Isolate affected system immediately. Preserve forensic evidence. Notify security team and compliance officers.",
        "privilege_escalation": "Review and revoke excessive privileges. Audit recent privilege changes. Investigate lateral movement.",
        "malware_detected": "Isolate the affected host. Run full endpoint scan. Initiate incident response process.",
        "account_lockout": "Investigate source of repeated failed logins. Reset compromised credentials. Review authentication logs.",
        "login_failure": "Monitor for continued failures. Consider temporary IP block if pattern persists. Review user account status.",
    }
    base = actions.get(event_type, "Investigate the event. Review related logs. Escalate to security team if pattern continues.")
    if failed_logins >= 10:
        base += f" Note: {failed_logins} failed login attempts detected."
    if req_count >= 200:
        base += f" Note: Abnormally high request volume ({req_count} requests)."
    return base


# Module-level singleton
_engine: Optional[DetectionEngine] = None


def get_detection_engine() -> DetectionEngine:
    """Get or initialise the detection engine singleton."""
    global _engine
    if _engine is None:
        _engine = DetectionEngine()
        _engine.load()
    return _engine
