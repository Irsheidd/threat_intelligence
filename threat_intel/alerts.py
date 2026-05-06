from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ALERT_HISTORY: List[Dict[str, Any]] = []


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_alert_record(analysis: Dict[str, Any]) -> Dict[str, Any]:
    severity = analysis.get('threat_level', 'low')
    title = analysis.get('issue', 'Suspicious activity detected')
    description = analysis.get('description', 'Unusual network behavior was identified.')
    recommended_action = analysis.get(
        'recommended_action',
        'Review the affected session and isolate any suspicious activity.',
    )

    summary = f"[{severity.upper()}] {title}: {description}"

    alert = {
        'id': f"alert-{len(ALERT_HISTORY) + 1}",
        'timestamp': _utc_now(),
        'session_id': analysis.get('session_id'),
        'src_ip': analysis.get('src_ip'),
        'dst_ip': analysis.get('dst_ip'),
        'anomaly_score': analysis.get('anomaly_score'),
        'threat_level': severity,
        'issue': title,
        'description': description,
        'recommended_action': recommended_action,
        'summary': summary,
        'evidence': analysis.get('evidence', []),
    }
    ALERT_HISTORY.append(alert)
    return alert


def list_alerts(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    alerts = ALERT_HISTORY[-limit:] if limit else ALERT_HISTORY
    return deepcopy(alerts)


def clear_alerts() -> None:
    ALERT_HISTORY.clear()


def get_alert_summary() -> Dict[str, Any]:
    alerts = list_alerts()
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for alert in alerts:
        severity = alert.get('threat_level', 'low')
        if severity not in severity_counts:
            severity_counts[severity] = 0
        severity_counts[severity] += 1

    latest_alert = alerts[-1] if alerts else None
    return {
        'total_alerts': len(alerts),
        'severity_counts': severity_counts,
        'latest_alert': latest_alert,
    }
