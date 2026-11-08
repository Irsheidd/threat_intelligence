from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, url_for

CURRENT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = CURRENT_DIR.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from threat_intel.alerts import get_alert_summary, list_alerts
from threat_intel.pipeline import run_threat_pipeline

MAX_LOG_LINES = 5000

app = Flask(__name__, template_folder='templates')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # reject request bodies over 2 MB


def _coerce_logs(payload: dict) -> list[str]:
    logs = payload.get('logs') or payload.get('log')
    if not logs:
        raise ValueError('Missing logs. Provide "logs" as a list or "log" as a single entry.')
    if not isinstance(logs, list):
        logs = [logs]
    if len(logs) > MAX_LOG_LINES:
        raise ValueError(f'Too many log entries ({len(logs)}); the limit is {MAX_LOG_LINES} per request.')
    return logs


def _run_detection(logs: list[str]) -> dict:
    result = run_threat_pipeline(logs)
    return {
        'count': result['count'],
        'suspicious_count': result['suspicious_count'],
        'normal_count': result['normal_count'],
        'highest_severity': result['highest_severity'],
        'results': result['detections'],
        'analyses': result['analyses'],
        'alerts': result['alerts'],
    }


@app.route('/health', methods=['GET'])
def health() -> tuple[dict, int]:
    return {'status': 'ok'}, 200


@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('dashboard'))


@app.route('/ui', methods=['GET'])
def ui():
    return redirect(url_for('dashboard'))


@app.route('/dashboard', methods=['GET'])
def dashboard():
    summary = get_alert_summary()
    alerts = list_alerts(limit=20)
    return render_template('dashboard.html', summary=summary, alerts=alerts)


@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    return jsonify({
        'alerts': list_alerts(limit=50),
        'summary': get_alert_summary(),
    }), 200


@app.route('/api/summary', methods=['GET'])
def api_summary():
    return jsonify(get_alert_summary()), 200


@app.route('/detect', methods=['GET', 'POST'])
def detect():
    if request.method == 'GET':
        return jsonify({
            'message': 'Use POST with JSON body {"logs": [ ... ]} or {"log": "..." }',
            'example_endpoint': '/detect',
        }), 200

    payload = request.get_json(silent=True) or {}
    try:
        logs = _coerce_logs(payload)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    try:
        result = _run_detection(logs)
    except FileNotFoundError as exc:
        return jsonify({'error': str(exc)}), 500
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception:
        return jsonify({'error': 'Model prediction failed.'}), 500

    return jsonify(result), 200


if __name__ == '__main__':
    port = int(os.getenv('PORT', '5002'))
    app.run(host='0.0.0.0', port=port, debug=False)
