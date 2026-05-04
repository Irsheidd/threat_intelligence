import os
import pandas as pd
import psycopg2
import psycopg2.extras as extras
import dotenv
dotenv.load_dotenv(override=True)  # Prefer the project .env over inherited shell variables



def connect_db():
    # DATABASE_URL is loaded from .env unless explicitly overridden in the shell
    dsn = os.getenv('DATABASE_URL')
    conn = psycopg2.connect(dsn)
    return conn


def create_table(conn, table='network_features'):
    create_sql = f"""
    CREATE TABLE IF NOT EXISTS {table} (
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
    """
    with conn.cursor() as cur:
        cur.execute(create_sql)
    conn.commit()


def insert_dataframe(conn, df, table='network_features'):
    # Upsert is not included for simplicity; duplicates will conflict on primary key
    cols = list(df.columns)
    # sanitize and convert to tuples
    values = []
    for row in df[cols].itertuples(index=False, name=None):
        safe = []
        for v in row:
            if pd.isna(v):
                safe.append(None)
            else:
                safe.append(v)
        values.append(tuple(safe))

    cols_sql = ','.join(cols)
    sql = f"INSERT INTO {table} ({cols_sql}) VALUES %s ON CONFLICT (session_id) DO UPDATE SET " + \
          ','.join([f"{c}=EXCLUDED.{c}" for c in cols if c != 'session_id'])

    with conn.cursor() as cur:
        extras.execute_values(cur, sql, values, template=None, page_size=1000)
    conn.commit()
