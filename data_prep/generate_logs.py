"""Generate a labelled synthetic network-log dataset.

    python -m data_prep.generate_logs            # writes sources/synthetic_logs.csv

Each session follows one scenario. The `stage` column carries the scenario name
and `label` is `suspicious` or `normal` (the same vocabulary as sources/network_logs.csv); neither is used as a model feature, they
exist only to evaluate the unsupervised detector afterwards.

Normal traffic deliberately overlaps with attacks (some legitimate users log in
from abroad, mistype passwords or upload large files), so no single rule
separates the classes and the evaluation means something.
"""

import argparse
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

FIELDS = ["timestamp", "user_id", "session_id", "src_ip", "dst_ip", "country", "event_type",
          "action", "status", "bytes", "stage", "label"]

# share of sessions per scenario; attacks total 15%, matching the model's contamination
SCENARIOS = {
    "normal_browsing": 0.55,
    "normal_login": 0.20,
    "normal_upload": 0.10,
    "brute_force": 0.05,
    "port_scan": 0.04,
    "exfiltration": 0.03,
    "foreign_login": 0.03,
}
ATTACKS = {"brute_force", "port_scan", "exfiltration", "foreign_login"}
HOME_COUNTRIES = ["JO"] * 7 + ["US"] * 3
TRAVEL_COUNTRIES = ["DE", "GB", "AE", "SA", "TR"]
HOSTILE_COUNTRIES = ["RU", "CN", "IR", "BR", "KP", "VN"]
SERVERS = [f"10.0.0.{i}" for i in range(2, 30)]


class SessionWriter:
    def __init__(self, rng, start):
        self.rng, self.start, self.rows, self.n = rng, start, [], 0

    def _clock(self, night=False):
        day = self.start + timedelta(days=self.rng.randrange(7))
        hour = self.rng.choice([0, 1, 2, 3, 4, 5]) if night else min(23, max(0, int(self.rng.gauss(14, 3))))
        return day.replace(hour=hour, minute=self.rng.randrange(60), second=self.rng.randrange(60))

    def session(self, scenario, user, src_ip, country, events, night=False, gap=(5, 120)):
        """events: list of (event_type, action, status, bytes, dst_ip) tuples."""
        self.n += 1
        sid, t = f"sess_{self.n:05d}", self._clock(night)
        label = "suspicious" if scenario in ATTACKS else "normal"
        for event_type, action, status, size, dst in events:
            self.rows.append([t.isoformat(timespec="seconds"), user, sid, src_ip, dst, country,
                              event_type, action, status, size, scenario, label])
            t += timedelta(seconds=self.rng.uniform(*gap))


def generate(n_sessions=1500, seed=7):
    rng = random.Random(seed)
    w = SessionWriter(rng, datetime(2026, 5, 4))
    users = [f"user_{i}" for i in range(1, 301)]
    home_ip = {u: f"192.168.{1 + i // 250}.{10 + i % 240}" for i, u in enumerate(users)}
    attacker_ips = [f"203.0.113.{i}" for i in range(1, 40)] + [f"198.51.100.{i}" for i in range(1, 40)]

    def server():
        return rng.choice(SERVERS)

    def normal_country():
        return rng.choice(TRAVEL_COUNTRIES) if rng.random() < 0.05 else rng.choice(HOME_COUNTRIES)

    names, weights = zip(*SCENARIOS.items())
    for scenario in rng.choices(names, weights, k=n_sessions):
        user = rng.choice(users)
        if scenario == "normal_browsing":
            dst = server()
            events = [("web", "GET", "success", rng.randint(400, 6000), dst) for _ in range(rng.randint(1, 15))]
            w.session(scenario, user, home_ip[user], normal_country(), events)
        elif scenario == "normal_login":
            dst = server()
            events = [("login", "LOGIN", "failed", rng.randint(300, 900), dst)] if rng.random() < 0.15 else []
            events.append(("login", "LOGIN", "success", rng.randint(300, 900), dst))
            events += [("web", "GET", "success", rng.randint(400, 6000), dst) for _ in range(rng.randint(0, 8))]
            w.session(scenario, user, home_ip[user], normal_country(), events)
        elif scenario == "normal_upload":
            dst = server()
            events = [("login", "LOGIN", "success", rng.randint(300, 900), dst)]
            events += [("data_transfer", "UPLOAD", "success", rng.randint(2000, 40000), dst)
                       for _ in range(rng.randint(1, 4))]
            w.session(scenario, user, home_ip[user], normal_country(), events)
        elif scenario == "brute_force":
            dst = server()
            events = [("login", "LOGIN", "failed", rng.randint(300, 900), dst) for _ in range(rng.randint(5, 25))]
            if rng.random() < 0.3:
                events.append(("login", "LOGIN", "success", rng.randint(300, 900), dst))
            country = rng.choice(HOSTILE_COUNTRIES) if rng.random() < 0.7 else "JO"
            w.session(scenario, user, rng.choice(attacker_ips), country, events, gap=(0.5, 3))
        elif scenario == "port_scan":
            events = [("scan", "SCAN", rng.choice(["failed", "failed", "success"]), rng.randint(60, 400), server())
                      for _ in range(rng.randint(10, 40))]
            w.session(scenario, "unknown", rng.choice(attacker_ips), rng.choice(HOSTILE_COUNTRIES + ["US"]),
                      events, gap=(0.1, 1.5))
        elif scenario == "exfiltration":
            dst = server()
            events = [("login", "LOGIN", "success", rng.randint(300, 900), dst)]
            events += [("data_transfer", "UPLOAD", "success", rng.randint(60000, 600000), rng.choice(SERVERS))
                       for _ in range(rng.randint(3, 10))]
            w.session(scenario, user, home_ip[user], "JO", events, night=True, gap=(10, 90))
        elif scenario == "foreign_login":
            dst = server()
            events = [("login", "LOGIN", "success", rng.randint(300, 900), dst)]
            events += [("web", "GET", "success", rng.randint(400, 6000), dst) for _ in range(rng.randint(1, 5))]
            w.session(scenario, user, rng.choice(attacker_ips), rng.choice(HOSTILE_COUNTRIES), events)

    return sorted(w.rows, key=lambda r: r[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sessions", type=int, default=1500)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=Path, default=Path("sources/synthetic_logs.csv"))
    args = parser.parse_args()

    rows = generate(args.sessions, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(FIELDS)
        writer.writerows(rows)
    attacks = len({r[2] for r in rows if r[11] == "suspicious"})
    print(f"wrote {len(rows)} events in {args.sessions} sessions ({attacks} attack sessions) to {args.out}")


if __name__ == "__main__":
    main()
