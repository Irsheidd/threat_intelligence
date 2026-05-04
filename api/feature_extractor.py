import os
from typing import Any, Dict, List

import pandas as pd

from data_prep.feature_engineering import compute_features, parse_line_regex


REQUIRED_COLUMNS = [
    'timestamp',
    'user_id',
    'session_id',
    'src_ip',
    'dst_ip',
    'country',
    'event_type',
    'action',
    'status',
    'bytes',
    'stage',
    'label',
]

DEFAULTS = {
    'user_id': 'unknown',
    'action': 'UNKNOWN',
    'status': 'unknown',
    'bytes': 0,
    'stage': 'unknown',
    'label': 'unknown',
}


def _normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    normalized = {k: record.get(k) for k in REQUIRED_COLUMNS}
    for key, value in DEFAULTS.items():
        if not normalized.get(key):
            normalized[key] = value
    if normalized.get('bytes') is None:
        normalized['bytes'] = 0
    try:
        normalized['bytes'] = int(normalized['bytes'])
    except (TypeError, ValueError):
        normalized['bytes'] = 0
    return normalized


def _parse_log_entry(entry: Any) -> Dict[str, Any]:
    if isinstance(entry, str):
        parsed = parse_line_regex(entry)
        if not parsed:
            # fallback: try generic CSV split
            parts = [p.strip() for p in entry.split(',')]
            if len(parts) >= 12:
                try:
                    parsed = {
                        'timestamp': parts[0],
                        'user_id': parts[1],
                        'session_id': parts[2],
                        'src_ip': parts[3],
                        'dst_ip': parts[4],
                        'country': parts[5],
                        'event_type': parts[6],
                        'action': parts[7],
                        'status': parts[8],
                        'bytes': int(parts[9]) if parts[9].isdigit() else 0,
                        'stage': parts[10],
                        'label': parts[11]
                    }
                except (ValueError, IndexError) as e:
                    raise ValueError(f'Log entry does not match expected CSV format (12 comma-separated fields): {entry[:100]}')
            else:
                raise ValueError(f'Log entry has {len(parts)} fields, expected 12. Entry: {entry[:100]}')
        return _normalize_record(parsed)
    if isinstance(entry, dict):
        if not entry.get('session_id'):
            raise ValueError('Log entry missing session_id.')
        if not entry.get('timestamp'):
            raise ValueError('Log entry missing timestamp.')
        return _normalize_record(entry)
    raise ValueError('Log entry must be a string or JSON object.')


def build_features_from_logs(logs: List[Any]) -> pd.DataFrame:
    if not logs:
        raise ValueError('No log entries provided.')
    records = [_parse_log_entry(entry) for entry in logs]
    df = pd.DataFrame(records)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return compute_features(df)


def numeric_matrix(features: pd.DataFrame) -> pd.DataFrame:
    numeric = features.select_dtypes(include=['number']).copy()
    if 'label' in numeric.columns:
        numeric = numeric.drop(columns=['label'])
    return numeric
