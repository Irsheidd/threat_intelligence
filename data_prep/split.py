"""One train/test split of sessions, shared by training and evaluation."""

from sklearn.model_selection import train_test_split

TEST_SIZE = 0.3
SEED = 42


def split_sessions(features):
    """Stratified by label when labels exist, so both splits keep the same attack rate.

    The detector never sees labels; they only keep the held-out split representative.
    """
    stratify = features["label"] if "label" in features and features["label"].nunique() > 1 else None
    return train_test_split(features, test_size=TEST_SIZE, random_state=SEED, stratify=stratify)
