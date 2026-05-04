import os
import re
import pandas as pd
import numpy as np
from datetime import timedelta

from . import db


def parse_line_regex(line):
    # pattern for CSV-like lines with 12 fields
    pattern = re.compile(r"^(?P<timestamp>[^,]+),(?P<user_id>[^,]+),(?P<session_id>[^,]+),(?P<src_ip>[^,]+),(?P<dst_ip>[^,]+),(?P<country>[^,]+),(?P<event_type>[^,]+),(?P<action>[^,]+),(?P<status>[^,]+),(?P<bytes>[^,]+),(?P<stage>[^,]+),(?P<label>[^\n]+)")
    m = pattern.match(line)
    if not m:
        return None
    d = m.groupdict()
    # convert types
    try:
        d['bytes'] = int(d.get('bytes') or 0)
    except ValueError:
        d['bytes'] = 0
    return d


def load_logs(path):
    records = []
    with open(path, 'r', encoding='utf-8') as f:
        header = f.readline()
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            parsed = parse_line_regex(line)
            if parsed:
                records.append(parsed)
            else:
                # fallback: try splitting CSV
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 12:
                    rec = {
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
                    records.append(rec)
    df = pd.DataFrame(records)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp')
    return df


def compute_features(df):
    # global frequency per src_ip
    ip_freq = df.groupby('src_ip').size().rename('ip_request_freq')

    def agg_session(g):
        session = {}
        session['session_id'] = g.name
        session['user_id'] = g['user_id'].mode().iloc[0] if not g['user_id'].mode().empty else 'unknown'
        session['src_ip'] = g['src_ip'].mode().iloc[0]
        session['country'] = g['country'].mode().iloc[0]
        session['start_time'] = g['timestamp'].min()
        session['end_time'] = g['timestamp'].max()
        session['duration_seconds'] = (session['end_time'] - session['start_time']).total_seconds()
        session['num_events'] = len(g)
        session['total_bytes'] = g['bytes'].sum()
        session['avg_bytes_per_event'] = g['bytes'].mean()
        session['distinct_dst_ips'] = g['dst_ip'].nunique()
        session['num_failed_logins'] = int(((g['event_type'] == 'login') & (g['status'] == 'failed')).sum())
        session['num_success_logins'] = int(((g['event_type'] == 'login') & (g['status'] == 'success')).sum())
        session['num_web'] = int((g['event_type'] == 'web').sum())
        session['num_data_transfer'] = int((g['event_type'] == 'data_transfer').sum())
        session['num_scan'] = int((g['event_type'] == 'scan').sum())
        session['hour_of_day'] = int(session['start_time'].hour)
        session['requests_per_minute'] = (session['num_events'] / (max(session['duration_seconds'], 1) / 60.0))
        session['ip_request_freq'] = int(ip_freq.loc[session['src_ip']])
        # unusual country heuristic: mark if not JO (adjustable)
        session['country_unusual'] = 0 if session['country'] in ('JO', 'US') else 1
        # label (majority) if available
        session['label'] = g['label'].mode().iloc[0] if not g['label'].mode().empty else 'unknown'
        return pd.Series(session)

    features = df.groupby('session_id').apply(agg_session).reset_index(drop=True)
    # fill NaNs and types
    features['duration_seconds'] = features['duration_seconds'].fillna(0).astype(float)
    features['requests_per_minute'] = features['requests_per_minute'].replace([np.inf, -np.inf], 0).fillna(0)
    return features


def main():
    src = os.path.join('sources', 'network_logs.csv')
    out_dir = os.path.join('data_prep', 'outputs')
    os.makedirs(out_dir, exist_ok=True)

    print('Loading logs...')
    df = load_logs(src)

    print('Computing features...')
    feats = compute_features(df)

    out_csv = os.path.join(out_dir, 'features_dataset.csv')
    feats.to_csv(out_csv, index=False)
    print(f'Features written to {out_csv}')

    # attempt DB save if DATABASE_URL present
    db_url = os.environ.get('DATABASE_URL')
    if db_url:
        print('Connecting to database...')
        conn = db.connect_db()
        print('Creating table if needed...')
        db.create_table(conn)
        print('Inserting features into database...')
        db.insert_dataframe(conn, feats, table='network_features')
        conn.close()
        print('Saved features to database table `network_features`.')
    else:
        print('DATABASE_URL not set; skipping DB save. To enable, set env var DATABASE_URL.')


if __name__ == '__main__':
    main()
