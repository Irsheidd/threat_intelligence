"""Evaluate the trained Isolation Forest on held-out sessions.

    # held-out 30% of the dataset the model was trained on
    python -m data_prep.evaluate --logs sources/synthetic_logs.csv --out reports/synthetic
    # every session of a dataset the model never saw
    python -m data_prep.evaluate --logs sources/network_logs.csv --split all --out reports/project

Scores sessions with the saved model and the same alerting logic as the API
(threat_intel.pipeline), then writes metrics.json and score_distribution.png.
"""

import argparse
import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score

from data_prep.feature_engineering import compute_features, load_logs
from data_prep.model import MODEL_DIR, prepare_matrix
from data_prep.split import split_sessions
from threat_intel.pipeline import _build_analysis


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--logs", type=Path, default=Path("sources/synthetic_logs.csv"))
    parser.add_argument("--split", choices=["test", "all"], default="test",
                        help="test: the held-out split model.py did not train on; all: every session")
    parser.add_argument("--out", type=Path, default=Path("reports/synthetic"))
    args = parser.parse_args()

    logs = load_logs(args.logs)
    features = compute_features(logs)
    test = split_sessions(features)[1] if args.split == "test" else features
    model = joblib.load(Path(MODEL_DIR) / "isolation_forest.joblib")

    X = prepare_matrix(test)
    raw_scores = model.decision_function(X)  # below 0 = anomalous
    flagged = model.predict(X) == -1
    is_attack = (test["label"] != "normal").to_numpy()

    precision, recall, f1, _ = precision_recall_fscore_support(is_attack, flagged, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(is_attack, flagged, labels=[False, True]).ravel()

    scenario = logs.groupby("session_id")["stage"].agg(lambda s: s.mode().iloc[0])
    test_scenarios = scenario.reindex(test["session_id"]).to_numpy()
    per_scenario = {}
    for name in sorted(set(test_scenarios)):
        mask = test_scenarios == name
        key = "false_alarm_rate" if name.startswith("normal") else "detection_rate"
        per_scenario[name] = {"sessions": int(mask.sum()), key: round(float(flagged[mask].mean()), 3)}

    severities = {"attack": {}, "normal": {}}
    for (_, row), score, hit, attack in zip(test.iterrows(), raw_scores, flagged, is_attack):
        if hit:
            level = _build_analysis(row, float(score), -1)["threat_level"]
            bucket = severities["attack" if attack else "normal"]
            bucket[level] = bucket.get(level, 0) + 1

    metrics = {
        "dataset": str(args.logs.as_posix()),
        "split": args.split,
        "test_sessions": int(len(test)),
        "attack_sessions": int(is_attack.sum()),
        "precision": round(float(precision), 3),
        "recall": round(float(recall), 3),
        "f1": round(float(f1), 3),
        "roc_auc": round(float(roc_auc_score(is_attack, -raw_scores)), 3),
        "average_precision": round(float(average_precision_score(is_attack, -raw_scores)), 3),
        "confusion": {"true_negative": int(tn), "false_positive": int(fp), "false_negative": int(fn), "true_positive": int(tp)},
        "per_scenario": per_scenario,
        "alert_severity_of_flagged_sessions": severities,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2))

    bins = np.linspace(raw_scores.min(), raw_scores.max(), 40)
    plt.figure(figsize=(9, 4.5))
    plt.hist(raw_scores[~is_attack], bins=bins, alpha=0.7, label="normal sessions", color="#2c7fb8")
    plt.hist(raw_scores[is_attack], bins=bins, alpha=0.7, label="attack sessions", color="#d95f0e")
    plt.axvline(0, color="black", linestyle="--", linewidth=1, label="decision threshold")
    plt.xlabel("Isolation Forest decision score (lower = more anomalous)")
    plt.ylabel("sessions")
    plt.legend()
    plt.tight_layout()
    plt.savefig(args.out / "score_distribution.png", dpi=150)

    print(json.dumps({k: metrics[k] for k in ("precision", "recall", "f1", "roc_auc", "average_precision")}))
    print(json.dumps(per_scenario))


if __name__ == "__main__":
    main()
