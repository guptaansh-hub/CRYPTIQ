import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import pytest

from scripts.baseline_original_elliptic import (
    N_LOCAL_FEATURES,
    N_AGG_FEATURES,
    N_TOTAL_FEATURES,
    resolve_raw_dir,
    load_original_elliptic_data,
    partition_temporal_splits,
    check_leakage_and_graph_integrity,
    compute_metrics,
    compute_timestep_breakdown,
    train_and_evaluate_baseline,
)


@pytest.fixture()
def mock_elliptic_data(tmp_path):
    """Creates a miniature synthetic version of the original Elliptic dataset files."""
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # 30 transactions across time steps 1 to 45
    # ts 1..34: train
    # ts 35..39: val
    # ts 40..45: test
    rows = []
    classes = []
    edges = []

    rng = np.random.RandomState(42)

    for i in range(1, 31):
        tx_id = 1000 + i
        if i <= 15:
            ts = i * 2  # 2, 4, ..., 30 (train)
        elif i <= 22:
            ts = 35 + (i - 16)  # 35, 36, 37, 38, 39, 40, 41
        else:
            ts = 42 + (i - 23)  # 42, 43, 44, 45, 46, 47, 48, 49

        # Class: assign roughly 1 (illicit), 2 (licit), or unknown
        if i % 5 == 0:
            c = "unknown"
        elif i % 2 == 0:
            c = "1"
        else:
            c = "2"

        classes.append({"txId": tx_id, "class": c})

        # 165 numeric features
        features = rng.randn(N_TOTAL_FEATURES).tolist()
        rows.append([tx_id, ts] + features)

    # Create intra-timestep edges (e.g. between consecutive nodes if they share ts, or self loops)
    # Give some pairs the same time step
    rows[1][1] = rows[0][1]  # ts of tx 1002 matches 1001
    edges.append({"txId1": 1001, "txId2": 1002})

    rows[16][1] = rows[15][1]  # ts match in val
    edges.append({"txId1": 1016, "txId2": 1017})

    # Write features (no header)
    feat_df = pd.DataFrame(rows)
    feat_df.to_csv(raw_dir / "elliptic_txs_features.csv", header=False, index=False)

    # Write classes
    class_df = pd.DataFrame(classes)
    class_df.to_csv(raw_dir / "elliptic_txs_classes.csv", index=False)

    # Write edges
    edge_df = pd.DataFrame(edges)
    edge_df.to_csv(raw_dir / "elliptic_txs_edgelist.csv", index=False)

    return raw_dir, tmp_path / "processed", tmp_path / "models"


def test_resolve_raw_dir(tmp_path):
    valid_raw = tmp_path / "valid_raw"
    valid_raw.mkdir()
    (valid_raw / "elliptic_txs_features.csv").write_text("dummy", encoding="utf-8")

    resolved = resolve_raw_dir(valid_raw)
    assert resolved == valid_raw

    with pytest.raises(FileNotFoundError):
        resolve_raw_dir(tmp_path / "nonexistent_dir")


def test_load_original_elliptic_data(mock_elliptic_data):
    raw_dir, _, _ = mock_elliptic_data
    df_meta, tx_ids, time_steps, X, y, feature_names = load_original_elliptic_data(
        raw_dir, exclude_unknown=True
    )

    # There were 30 total rows; 6 were "unknown" (i % 5 == 0: 5, 10, 15, 20, 25, 30)
    assert len(tx_ids) == 24
    assert len(y) == 24
    assert X.shape == (24, 165)
    assert len(feature_names) == 165

    # Check label mapping: class 1 -> 1, class 2 -> 0
    assert set(np.unique(y)) <= {0, 1}
    assert (df_meta.loc[df_meta.class_raw == "1", "label"] == 1).all()
    assert (df_meta.loc[df_meta.class_raw == "2", "label"] == 0).all()


def test_partition_temporal_splits(mock_elliptic_data):
    raw_dir, _, _ = mock_elliptic_data
    _, tx_ids, time_steps, X, y, _ = load_original_elliptic_data(raw_dir, exclude_unknown=True)

    splits = partition_temporal_splits(
        tx_ids, time_steps, X, y, train_max_ts=34, val_min_ts=35, val_max_ts=39, test_min_ts=40, test_max_ts=49
    )

    assert "train" in splits and "val" in splits and "test" in splits

    train_ids = set(splits["train"]["tx_ids"])
    val_ids = set(splits["val"]["tx_ids"])
    test_ids = set(splits["test"]["tx_ids"])

    # Zero overlap across temporal partitions
    assert len(train_ids & val_ids) == 0
    assert len(train_ids & test_ids) == 0
    assert len(val_ids & test_ids) == 0

    assert (splits["train"]["time_steps"] <= 34).all()
    assert ((splits["val"]["time_steps"] >= 35) & (splits["val"]["time_steps"] <= 39)).all()
    assert (splits["test"]["time_steps"] >= 40).all()


def test_check_leakage_and_graph_integrity_clean_and_dirty(mock_elliptic_data):
    raw_dir, _, _ = mock_elliptic_data
    _, tx_ids, time_steps, X, y, _ = load_original_elliptic_data(raw_dir, exclude_unknown=True)

    feat_meta = pd.read_csv(raw_dir / "elliptic_txs_features.csv", header=None, usecols=[0, 1])
    tx_to_ts = dict(zip(feat_meta.iloc[:, 0].astype(int), feat_meta.iloc[:, 1].astype(int)))

    splits = partition_temporal_splits(tx_ids, time_steps, X, y)

    # 1. Clean check
    clean_findings = check_leakage_and_graph_integrity(raw_dir, splits, tx_to_ts)
    assert clean_findings["temporal_isolation"]["pass"] is True
    assert clean_findings["boundary_ordering"]["pass"] is True
    assert clean_findings["graph_integrity"]["cross_timestep_edges"] == 0
    assert clean_findings["graph_integrity"]["graph_temporal_isolation_pass"] is True

    # 2. Dirty check: inject an edge spanning train (ts 2) to test (ts 45)
    dirty_edges = pd.read_csv(raw_dir / "elliptic_txs_edgelist.csv")
    dirty_edges = pd.concat([
        dirty_edges,
        pd.DataFrame([{"txId1": 1001, "txId2": 1028}])
    ], ignore_index=True)
    dirty_edges_path = raw_dir / "elliptic_txs_edgelist.csv"
    dirty_edges.to_csv(dirty_edges_path, index=False)

    dirty_findings = check_leakage_and_graph_integrity(raw_dir, splits, tx_to_ts)
    assert dirty_findings["graph_integrity"]["cross_timestep_edges"] == 1
    assert dirty_findings["graph_integrity"]["cross_split_edges"] == 1
    assert dirty_findings["graph_integrity"]["graph_temporal_isolation_pass"] is False


def test_compute_metrics():
    y_true = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 1, 0, 1])
    y_prob = np.array([0.1, 0.7, 0.4, 0.9])

    m = compute_metrics(y_true, y_pred, y_prob)

    assert m["confusion_matrix"]["true_negatives_licit"] == 1
    assert m["confusion_matrix"]["false_positives_licit_as_illicit"] == 1
    assert m["confusion_matrix"]["false_negatives_illicit_as_licit"] == 1
    assert m["confusion_matrix"]["true_positives_illicit"] == 1

    assert m["illicit_class"]["precision"] == 0.5
    assert m["illicit_class"]["recall"] == 0.5
    assert m["illicit_class"]["f1"] == 0.5
    assert m["accuracy"] == 0.5
    assert m["roc_auc"] is not None


def test_end_to_end_baseline_synthetic(mock_elliptic_data):
    raw_dir, out_dir, models_dir = mock_elliptic_data

    result = train_and_evaluate_baseline(
        raw_dir=raw_dir,
        out_dir=out_dir,
        models_dir=models_dir,
        n_estimators=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=1,
    )

    assert (out_dir / "baseline_metrics.json").exists()
    assert (out_dir / "baseline_report.md").exists()
    assert (out_dir / "leakage_and_limitations.md").exists()
    assert (out_dir / "confusion_matrix_val.csv").exists()
    assert (out_dir / "confusion_matrix_test.csv").exists()
    assert (out_dir / "timestep_metrics.csv").exists()
    assert (models_dir / "original_elliptic_rf.joblib").exists()
    assert (models_dir / "original_elliptic_model_meta.json").exists()

    # Verify JSON content
    metrics_data = json.loads((out_dir / "baseline_metrics.json").read_text(encoding="utf-8"))
    assert "metrics" in metrics_data
    assert "leakage_checks" in metrics_data
    assert "train" in metrics_data["metrics"]
    assert "val" in metrics_data["metrics"]
    assert "test" in metrics_data["metrics"]

    # Verify model artifact loads and works
    loaded_model = joblib.load(models_dir / "original_elliptic_rf.joblib")
    dummy_input = np.random.randn(2, 165).astype(np.float32)
    preds = loaded_model.predict(dummy_input)
    assert len(preds) == 2
