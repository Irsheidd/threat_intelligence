import pandas as pd
import pytest

from data_prep.feature_engineering import compute_features
from data_prep.generate_logs import ATTACKS, FIELDS, generate
from threat_intel.alerts import clear_alerts
from threat_intel.pipeline import _threat_level, run_threat_pipeline

BRUTE_FORCE_THEN_EXFIL = [
    "2026-05-04T09:06:05,user_45,sess_025,192.168.1.65,10.0.0.2,JO,login,LOGIN,failed,820,suspicious,suspicious",
    "2026-05-04T09:06:06,user_45,sess_025,192.168.1.65,10.0.0.2,JO,login,LOGIN,failed,810,suspicious,suspicious",
    "2026-05-04T09:06:07,user_45,sess_025,192.168.1.65,10.0.0.2,JO,login,LOGIN,success,900,access,suspicious",
    "2026-05-04T09:06:08,user_45,sess_025,192.168.1.65,10.0.0.7,US,data_transfer,POST,success,13000,exfiltration,suspicious",
]
ORDINARY_BROWSING = [
    f"2026-05-05T14:0{i}:00,user_12,sess_100,192.168.1.70,10.0.0.3,JO,web,GET,success,2048,normal,normal"
    for i in range(5)
]


@pytest.fixture(autouse=True)
def fresh_alert_store():
    clear_alerts()
    yield
    clear_alerts()


def test_generator_is_deterministic_and_labelled():
    rows = generate(n_sessions=200, seed=1)
    assert rows == generate(n_sessions=200, seed=1)
    assert all(len(r) == len(FIELDS) for r in rows)
    sessions = {r[2]: r for r in rows}
    attack_share = sum(r[11] == "suspicious" for r in sessions.values()) / len(sessions)
    assert 0.05 < attack_share < 0.30
    assert {r[10] for r in rows if r[11] == "suspicious"} <= ATTACKS


def test_features_capture_failed_logins_and_scans():
    rows = generate(n_sessions=400, seed=3)
    df = pd.DataFrame(rows, columns=FIELDS)
    df["bytes"] = df["bytes"].astype(int)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    features = compute_features(df).set_index("session_id")
    stage = df.groupby("session_id")["stage"].first()

    brute = features.loc[stage[stage == "brute_force"].index]
    scans = features.loc[stage[stage == "port_scan"].index]
    assert (brute["num_failed_logins"] >= 5).all()
    assert (scans["num_scan"] >= 10).all() and (scans["distinct_dst_ips"] > 1).all()


def test_single_event_session_is_not_a_request_flood():
    # Regression: dividing by max(duration, 1 s) used to give one event 60 requests/minute.
    df = pd.DataFrame([ORDINARY_BROWSING[0].split(",")], columns=FIELDS)
    df["bytes"] = df["bytes"].astype(int)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    assert compute_features(df)["requests_per_minute"].iloc[0] == 1.0


def test_pipeline_flags_brute_force_with_exfiltration():
    result = run_threat_pipeline(BRUTE_FORCE_THEN_EXFIL)
    assert result["count"] == 1
    assert result["suspicious_count"] == 1
    assert result["alerts"][0]["threat_level"] in {"high", "critical"}


def test_pipeline_leaves_ordinary_browsing_alone():
    result = run_threat_pipeline(ORDINARY_BROWSING)
    assert result["suspicious_count"] == 0
    assert result["highest_severity"] == "low"


def test_pipeline_rejects_empty_input():
    with pytest.raises(ValueError):
        run_threat_pipeline([])


def test_shipped_model_generalises_to_the_project_dataset():
    # The model is trained on the synthetic benchmark; sources/network_logs.csv is never used for training.
    from data_prep.feature_engineering import load_logs
    from data_prep.model import prepare_matrix
    from threat_intel.pipeline import load_model

    logs = load_logs("sources/network_logs.csv")
    features = compute_features(logs)
    flagged = load_model().predict(prepare_matrix(features)) == -1
    stage = logs.groupby("session_id")["stage"].agg(lambda s: s.mode().iloc[0]).reindex(features["session_id"]).to_numpy()
    assert flagged[stage == "normal"].mean() <= 0.05
    assert flagged[stage == "brute_force"].mean() >= 0.9


def test_two_strong_signals_make_an_anomaly_critical():
    row = pd.Series({"num_failed_logins": 6, "country_unusual": 1, "num_data_transfer": 0,
                     "total_bytes": 0, "requests_per_minute": 3})
    assert _threat_level(-0.02, row, -1) == "critical"
    assert _threat_level(0.10, row, 1) == "low"
