# data_prep

Scripts to turn raw `sources/network_logs.csv` into a feature-engineered dataset suitable for ML, and optionally save into PostgreSQL.

Usage

1. Install dependencies (use virtualenv / venv):

```bash
pip install -r data_prep/requirements.txt
```

2. (Optional) Set database URL:

```bash
export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
```

3. Run feature creation:

```bash
python -m data_prep.feature_engineering
```

Output

- `data_prep/outputs/features_dataset.csv` — cleaned numeric dataset ready for modeling.
- If `DATABASE_URL` is set the script will create a `network_features` table and upsert rows.
