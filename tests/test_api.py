import pytest

from api.app import MAX_LOG_LINES, app
from threat_intel.alerts import clear_alerts

SAMPLE = [
    "2026-05-04T09:06:05,user_45,sess_025,192.168.1.65,10.0.0.2,JO,login,LOGIN,failed,820,suspicious,suspicious",
    "2026-05-04T09:06:06,user_45,sess_025,192.168.1.65,10.0.0.2,JO,login,LOGIN,failed,810,suspicious,suspicious",
    "2026-05-04T09:06:08,user_45,sess_025,192.168.1.65,10.0.0.7,US,data_transfer,POST,success,13000,exfiltration,suspicious",
]


@pytest.fixture
def client():
    clear_alerts()
    with app.test_client() as c:
        yield c
    clear_alerts()


def test_health(client):
    assert client.get("/health").get_json() == {"status": "ok"}


def test_detect_returns_results_and_stores_alerts(client):
    response = client.post("/detect", json={"logs": SAMPLE})
    assert response.status_code == 200
    body = response.get_json()
    assert body["count"] == 1 and body["suspicious_count"] == 1
    assert client.get("/api/summary").get_json()["total_alerts"] == 1


def test_detect_rejects_missing_logs(client):
    assert client.post("/detect", json={}).status_code == 400


def test_detect_rejects_malformed_lines(client):
    assert client.post("/detect", json={"logs": ["not,a,log"]}).status_code == 400


def test_detect_caps_batch_size(client):
    response = client.post("/detect", json={"logs": SAMPLE[:1] * (MAX_LOG_LINES + 1)})
    assert response.status_code == 400


def test_url_fetching_endpoint_is_gone(client):
    # /detect_url fetched arbitrary URLs server-side (SSRF); it was removed.
    assert client.post("/detect_url", data={"url": "http://169.254.169.254/"}).status_code == 404


def test_dashboard_escapes_log_supplied_fields(client):
    hostile = [line.replace("sess_025", "<script>alert(1)</script>") for line in SAMPLE]
    assert client.post("/detect", json={"logs": hostile}).get_json()["suspicious_count"] == 1
    html = client.get("/dashboard").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
