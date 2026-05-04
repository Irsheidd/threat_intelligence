import os

import joblib
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import IsolationForest


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


def main():
	df = load_features()
	X = prepare_matrix(df)
	model = train_isolation_forest(X)
	save_results(df, model, X)
	anomaly_count = (model.predict(X) == -1).sum()
	print(f'Training complete. Anomalies flagged: {anomaly_count}/{len(df)}')
	print(f'Results saved to: {RESULTS_CSV}')
	print(f'Model saved to: {os.path.join(MODEL_DIR, "isolation_forest.joblib")}')
	print(f'Plot saved to: {PLOT_PATH}')


if __name__ == '__main__':
	main()