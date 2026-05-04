import os
import sys

import joblib
import logging
from flask import Flask, jsonify, request
from flask import render_template_string


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from api.feature_extractor import build_features_from_logs, numeric_matrix


MODEL_PATH = os.path.join(PROJECT_ROOT, 'data_prep', 'outputs', 'models', 'isolation_forest.joblib')

app = Flask(__name__)
_model = None

# basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('threat-detection-api')


def _load_model():
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            logger.error('Model not found: %s', MODEL_PATH)
            raise FileNotFoundError(f'Model not found: {MODEL_PATH}')
        try:
            _model = joblib.load(MODEL_PATH)
        except Exception as e:
            logger.exception('Failed loading model: %s', e)
            raise
    return _model


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'service': 'threat-detection-api',
        'status': 'ok',
        'routes': ['/health', '/detect']
    }), 200


# Simple UI to input a URL containing log lines (one per line)
UI_HTML = '''
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Threat Detection UI</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 20px; }
      form { background: #f5f5f5; padding: 20px; border-radius: 5px; width: 60%; }
      input { width: 90%; padding: 8px; margin: 10px 0; }
      button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; }
      button:hover { background: #0056b3; }
      code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
      .format { background: #fff3cd; padding: 15px; margin: 20px 0; border-left: 4px solid #ffc107; }
    </style>
  </head>
  <body>
    <h1>Threat Detection System</h1>
    <h2>Option 1: Detect from URL</h2>
    <p>Provide a URL to a text file containing network logs (one log per line).</p>
    <form method="post" action="/detect_url">
      <label for="url"><strong>Log URL:</strong></label>
      <input type="url" id="url" name="url" placeholder="https://example.com/logs.txt" required />
      <button type="submit">Detect Threats</button>
    </form>
    
    <div class="format">
      <h3>Expected Log Format</h3>
      <p>Each log line must be CSV with 12 comma-separated fields:</p>
      <code>timestamp, user_id, session_id, src_ip, dst_ip, country, event_type, action, status, bytes, stage, label</code>
      <p><strong>Example:</strong></p>
      <code>2026-05-04T09:06:05, user_45, sess_025, 192.168.1.65, 10.0.0.2, JO, login, LOGIN, failed, 820, suspicious, suspicious</code>
    </div>
    
    <h2>Option 2: JSON API</h2>
    <p>Use <code>POST /detect</code> with JSON body:</p>
    <code>{ "logs": ["&lt;log-line-1&gt;", "&lt;log-line-2&gt;"] }</code>
  </body>
</html>
'''


@app.route('/ui', methods=['GET'])
def ui():
    return render_template_string(UI_HTML)


@app.route('/detect_url', methods=['POST'])
def detect_url():
    url = request.form.get('url')
    if not url:
        return 'Missing url form parameter', 400

    try:
        import requests
    except ImportError:
        return 'Python package "requests" is required on the server. Install with: pip install requests', 500

    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        logger.exception('Failed to fetch URL: %s', e)
        return f'Failed to fetch URL: {e}', 400

    # assume plain text with one log entry per line
    text = resp.text
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        html_err = '<h2>Error</h2><p>No log lines found at provided URL.</p>'
        html_err += '<a href="/ui">Back</a>'
        return html_err, 400

    logger.info('Fetched %d lines from URL. Attempting to parse...', len(lines))
    try:
        features = build_features_from_logs(lines)
    except Exception as e:
        logger.exception('Failed to build features from fetched logs: %s', e)
        error_msg = str(e)
        # show first 3 lines as examples
        sample_lines = '<br>'.join([f'<code>{ln[:100]}</code>' for ln in lines[:3]])
        html_err = f'<h2>Error parsing logs</h2><p>{error_msg}</p>'
        html_err += f'<h3>Sample lines (showing first {min(3, len(lines))} of {len(lines)}):</h3><p>{sample_lines}</p>'
        html_err += '<p>Expected format: 12 comma-separated fields (timestamp, user_id, session_id, src_ip, dst_ip, country, event_type, action, status, bytes, stage, label)</p>'
        html_err += '<a href="/ui">Back</a>'
        return html_err, 400

    try:
        model = _load_model()
    except Exception as e:
        return f'Model load error: {e}', 500

    matrix = numeric_matrix(features)
    matrix_np = matrix.values if hasattr(matrix, 'values') else matrix
    try:
        scores = model.decision_function(matrix_np)
        preds = model.predict(matrix_np)
    except Exception as e:
        logger.exception('Prediction failed: %s', e)
        return 'Model prediction failed', 500

    # render simple HTML results
    rows = []
    for i in range(len(features)):
        sid = features.iloc[i].get('session_id') if 'session_id' in features.columns else None
        score = float(scores[i]) if i < len(scores) else None
        cls = 'anomaly' if (i < len(preds) and int(preds[i]) == -1) else 'normal'
        rows.append(f'<tr><td>{sid}</td><td>{score}</td><td>{cls}</td></tr>')

    html = '<table border="1"><tr><th>session_id</th><th>anomaly_score</th><th>classification</th></tr>' + '\n'.join(rows) + '</table>'
    return html, 200


@app.route('/detect', methods=['GET', 'POST'])
def detect():
    if request.method == 'GET':
        return jsonify({
            'message': 'Use POST with JSON body {"logs": [ ... ]} or {"log": "..." }',
            'example_endpoint': '/detect'
        }), 200

    payload = request.get_json(silent=True) or {}
    logs = payload.get('logs') or payload.get('log')

    if not logs:
        return jsonify({'error': 'Missing logs. Provide "logs" as a list or "log" as a single entry.'}), 400

    if not isinstance(logs, list):
        logs = [logs]

    try:
        features = build_features_from_logs(logs)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    try:
        model = _load_model()
    except FileNotFoundError as exc:
        return jsonify({'error': str(exc)}), 500
    except Exception as exc:
        return jsonify({'error': 'Failed loading model.'}), 500

    matrix = numeric_matrix(features)
    # ensure ndarray for sklearn
    matrix_np = matrix.values if hasattr(matrix, 'values') else matrix

    try:
        scores = model.decision_function(matrix_np)
        predictions = model.predict(matrix_np)
    except Exception as exc:
        logger.exception('Model prediction failed: %s', exc)
        return jsonify({'error': 'Model prediction failed.'}), 500

    results = []
    # align positional outputs with feature rows
    for i in range(len(features)):
        row = features.iloc[i]
        try:
            score = float(scores[i])
            pred = int(predictions[i])
        except Exception:
            score = None
            pred = None
        results.append({
            'session_id': row.get('session_id') if 'session_id' in row else None,
            'anomaly_score': score,
            'classification': 'anomaly' if pred == -1 else ('normal' if pred == 1 else 'unknown')
        })

    return jsonify({
        'count': len(results),
        'results': results
    }), 200


if __name__ == '__main__':
    port = int(os.getenv('PORT', '5002'))
    app.run(host='0.0.0.0', port=port, debug=False)
