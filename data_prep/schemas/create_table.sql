-- SQL schema for the network_features table
CREATE TABLE IF NOT EXISTS network_features (
    session_id TEXT PRIMARY KEY,
    user_id TEXT,
    src_ip TEXT,
    country TEXT,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    duration_seconds DOUBLE PRECISION,
    num_events INTEGER,
    total_bytes BIGINT,
    avg_bytes_per_event DOUBLE PRECISION,
    distinct_dst_ips INTEGER,
    num_failed_logins INTEGER,
    num_success_logins INTEGER,
    num_web INTEGER,
    num_data_transfer INTEGER,
    num_scan INTEGER,
    hour_of_day INTEGER,
    requests_per_minute DOUBLE PRECISION,
    ip_request_freq INTEGER,
    country_unusual INTEGER,
    label TEXT
);
