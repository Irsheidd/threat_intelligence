import os

import joblib
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import IsolationForest

from data_prep.split import split_sessions


FEATURES_CSV_CANDIDATES = [
	os.path.join('data_prep', 'outputs', 'features_dataset.csv'),
	os.path.join('sources', 'features_dataset.csv'),
]
MODEL_DIR = os.path.join('data_prep', 'outputs', 'models')
RESULTS_CSV = os.path.join('data_prep', 'outputs', 'anomaly_scores.csv')
PLOT_PATH = os.path.join('data_prep', 'outputs', 'anomaly_score_distribution.png')


def load_features():
	for path in FEATURES_CSV_CANDIDATES:
		if os.path.exists(path):
			return pd.read_csv(path)
	raise FileNotFoundError(f'Feature file not found in any of: {FEATURES_CSV_CANDIDATES}')


def prepare_matrix(df):
	numeric = df.select_dtypes(include=['number']).copy()
	if 'label' in numeric.columns:
		numeric = numeric.drop(columns=['label'])
	return numeric


def train_isolation_forest(X, contamination=0.15):
	model = IsolationForest(
		n_estimators=200,
		contamination=contamination,
		random_state=42,
		n_jobs=-1,
	)
	model.fit(X)
	return model


def save_results(df, model, X):
	os.makedirs(MODEL_DIR, exist_ok=True)

	scores = model.decision_function(X)
	predictions = model.predict(X)

	results = df.copy()
	results['anomaly_score'] = scores
	results['anomaly_label'] = ['anomaly' if pred == -1 else 'normal' for pred in predictions]
	results.to_csv(RESULTS_CSV, index=False)

	joblib.dump(model, os.path.join(MODEL_DIR, 'isolation_forest.joblib'))

	plt.figure(figsize=(10, 5))
	plt.hist(scores, bins=30, color='#2c7fb8', edgecolor='white')
	plt.title('Isolation Forest Anomaly Score Distribution')
	plt.xlabel('Anomaly Score')
	plt.ylabel('Count')
	plt.tight_layout()
	plt.savefig(PLOT_PATH, dpi=150)
	plt.close()


def estimate_contamination(train_df, default=0.15):
	"""Expected share of anomalies, taken from the training split's labels when they exist.

	The detector itself never sees labels; this only places its alert threshold. A fixed
	0.15 on a dataset that is 39% suspicious caps recall near 0.38 however well the
	scores rank sessions.
	"""
	if 'label' not in train_df or train_df['label'].nunique() < 2:
		return default
	share = float((train_df['label'] != 'normal').mean())
	return min(max(share, 0.01), 0.5)


def main():
	import argparse
	parser = argparse.ArgumentParser(description='Train the Isolation Forest on the training split.')
	parser.add_argument('--contamination', type=float,
	                    help='expected anomaly share (default: estimated from training-split labels, else 0.15)')
	args = parser.parse_args()

	df = load_features()
	# Fit on the training sessions only; data_prep/evaluate.py scores the held-out rest.
	train_df, _ = split_sessions(df)
	contamination = args.contamination or estimate_contamination(train_df)
	model = train_isolation_forest(prepare_matrix(train_df), contamination=contamination)
	X = prepare_matrix(df)
	save_results(df, model, X)
	anomaly_count = (model.predict(X) == -1).sum()
	print(f'Trained on {len(train_df)} sessions (contamination {contamination:.3f}). '
	      f'Anomalies flagged across all {len(df)}: {anomaly_count}')
	print(f'Results saved to: {RESULTS_CSV}')
	print(f'Model saved to: {os.path.join(MODEL_DIR, "isolation_forest.joblib")}')
	print(f'Plot saved to: {PLOT_PATH}')


if __name__ == '__main__':
	main()