from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List

import joblib
import pandas as pd

from api.feature_extractor import build_features_from_logs, numeric_matrix
from .alerts import create_alert_record

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = WORKSPACE_ROOT / 'data_prep' / 'outputs' / 'models' / 'isolation_forest.joblib'


@lru_cache(maxsize=1)
def load_model() -> Any:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f'Model not found: {MODEL_PATH}')
    return joblib.load(MODEL_PATH)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _threat_level(score: float, row: pd.Series, prediction: int) -> str:
    if prediction != -1 and score >= 0:
        return 'low'

    high_risk_signals = [
        _safe_int(row.get('num_failed_logins', 0)) >= 2,
        _safe_int(row.get('country_unusual', 0)) == 1,
        _safe_int(row.get('num_data_transfer', 0)) > 0 and _safe_int(row.get('total_bytes', 0)) >= 10000,
        _safe_int(row.get('requests_per_minute', 0)) >= 60,
    ]
    if score <= -0.15 or sum(high_risk_signals) >= 2:
        return 'critical'
    if score <= -0.05 or any(high_risk_signals):
        return 'high'
    return 'medium'


def _evidence(row: pd.Series, score: float, prediction: int) -> List[str]:
    evidence: List[str] = []
    if prediction == -1:
        evidence.append('Isolation Forest flagged the session as anomalous.')
    if _safe_int(row.get('num_failed_logins', 0)) >= 2:
        evidence.append('Multiple failed login attempts were observed.')
    if _safe_int(row.get('country_unusual', 0)) == 1:
        evidence.append(f"Traffic originated from an unusual country: {row.get('country')}.")
    if _safe_int(row.get('num_data_transfer', 0)) > 0 and _safe_int(row.get('total_bytes', 0)) >= 10000:
        evidence.append('The session moved a large amount of data.')
    if _safe_int(row.get('requests_per_minute', 0)) >= 60:
        evidence.append('Request volume was unusually high for the session duration.')
    evidence.append(f'Anomaly score: {score:.4f}')
    return evidence


def _description(row: pd.Series, score: float, prediction: int) -> str:
    src_ip = row.get('src_ip', 'unknown source')
    dst_ip = row.get('primary_dst_ip', row.get('dst_ip', 'unknown destination'))
    parts = [f'Suspicious traffic was observed from {src_ip} toward {dst_ip}.']
    if prediction == -1:
        parts.append('The detection model marked the session as anomalous.')
    if _safe_int(row.get('num_failed_logins', 0)) >= 2:
        parts.append('Repeated failed logins indicate possible credential abuse.')
    if _safe_int(row.get('num_data_transfer', 0)) > 0:
        parts.append('Outbound transfer activity suggests possible data movement.')
    if score < 0:
        parts.append('The anomaly score is below the normal operating range.')
    return ' '.join(parts)


def _recommended_action(row: pd.Series, severity: str) -> str:
    if severity == 'critical':
        return 'Isolate the session immediately, reset credentials, and investigate the source host and destination systems.'
    if severity == 'high':
        return 'Review the session, validate user access, and inspect the related source and destination IP addresses.'
    if severity == 'medium':
        return 'Monitor the session and confirm whether the activity matches expected user behavior.'
    return 'No immediate action required.'


def _build_analysis(row: pd.Series, score: float, prediction: int) -> Dict[str, Any]:
    severity = _threat_level(score, row, prediction)
    if severity == 'low':
        issue = 'Routine activity'
    else:
        issue = 'Suspicious network behavior'

    return {
        'session_id': row.get('session_id'),
        'user_id': row.get('user_id'),
        'src_ip': row.get('src_ip'),
        'dst_ip': row.get('primary_dst_ip', row.get('dst_ip')),
        'issue': issue,
        'description': _description(row, score, prediction),
        'threat_level': severity,
        'recommended_action': _recommended_action(row, severity),
        'anomaly_score': float(score),
        'classification': 'anomaly' if prediction == -1 else 'normal',
        'evidence': _evidence(row, score, prediction),
    }


def run_threat_pipeline(logs: Iterable[Any]) -> Dict[str, Any]:
    log_entries = list(logs)
    if not log_entries:
        raise ValueError('No log entries provided.')

    features = build_features_from_logs(log_entries)
    matrix = numeric_matrix(features)
    matrix_np = matrix.values if hasattr(matrix, 'values') else matrix

    model = load_model()
    scores = model.decision_function(matrix)
    predictions = model.predict(matrix)

    detections: List[Dict[str, Any]] = []
    analyses: List[Dict[str, Any]] = []
    alerts: List[Dict[str, Any]] = []

    for index in range(len(features)):
        row = features.iloc[index]
        score = float(scores[index])
        prediction = int(predictions[index])
        analysis = _build_analysis(row, score, prediction)
        detection = {
            'session_id': row.get('session_id'),
            'user_id': row.get('user_id'),
            'src_ip': row.get('src_ip'),
            'dst_ip': row.get('primary_dst_ip', row.get('dst_ip')),
            'anomaly_score': score,
            'classification': analysis['classification'],
            'is_suspicious': analysis['classification'] == 'anomaly' or score < 0,
        }
        detections.append(detection)
        analyses.append(analysis)

        if analysis['classification'] == 'anomaly' or score < 0:
            alerts.append(create_alert_record(analysis))

    alert_count = len(alerts)
    normal_count = len(detections) - alert_count
    highest_severity = 'low'
    severity_rank = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
    for alert in alerts:
        severity = alert.get('threat_level', 'low')
        if severity_rank.get(severity, 0) > severity_rank.get(highest_severity, 0):
            highest_severity = severity

    return {
        'count': len(detections),
        'suspicious_count': alert_count,
        'normal_count': normal_count,
        'highest_severity': highest_severity,
        'detections': detections,
        'analyses': analyses,
        'alerts': alerts,
    }
