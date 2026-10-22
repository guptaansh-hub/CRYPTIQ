import hashlib, json
from pathlib import Path

import pandas as pd
import pytest

from cryptiq_data.audit import run_audit
from cryptiq_data.io_utils import RawGuard, clean_address, classify_address, norm_col
from cryptiq_data.preprocess import Preprocessor, STEPS
from cryptiq_data.synthetic import build_fixture


def sha(d):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(d).glob("*.csv")}


@pytest.fixture()
def fx(tmp_path):
    raw = tmp_path / "raw"
    info = build_fixture(raw)
    return raw, tmp_path / "out", info


def codes(report, level=None):
    return {(f["code"], f["file"]) for f in report["findings"] if level in (None, f["level"])}


def test_norm_and_address_helpers():
    assert norm_col("Time step") == "time_step" and norm_col("num_txs_as receiver") == "num_txs_as_receiver"
    s = pd.Series([" 1abc ", "BC1QABC", "", None])
    out = clean_address(s)
    assert out.iloc[0] == "1abc" and out.iloc[1] == "bc1qabc" and pd.isna(out.iloc[2]) and pd.isna(out.iloc[3])
    assert classify_address(pd.Series(["not_an_address"])).iloc[0] == "other_or_invalid"


def test_output_inside_raw_rejected(tmp_path):
    (tmp_path / "raw").mkdir()
    with pytest.raises(ValueError):
        RawGuard(tmp_path / "raw", tmp_path / "raw" / "processed")


def test_audit_detects_defects_and_leaves_raw_untouched(fx):
    raw, out, _ = fx
    before = sha(raw)
    r = run_audit(raw, out, chunksize=5)
    assert sha(raw) == before
    c = codes(r)
    assert ("DUPLICATE_KEYS", "txs_features.csv") in c
    assert ("NONFINITE", "txs_features.csv") in c
    assert ("NULLS", "txs_features.csv") in c
    assert ("LABEL_CONFLICT", "txs_classes.csv") in c
    assert ("LABEL_CONFLICT", "wallets_classes.csv") in c
    assert ("SELF_LOOPS", "AddrAddr_edgelist.csv") in c
    assert ("ADDRESS_FORMAT", "AddrAddr_edgelist.csv") in c
    assert ("ADDRESS_WHITESPACE", "AddrTx_edgelist.csv") in c
    assert ("CROSS_TIMESTEP_EDGES", "txs_edgelist.csv") in c
    assert ("LEAKAGE_WHOLE_HISTORY", "wallets_features.csv") in c
    assert ("COMBINED_MISMATCH", "wallets_features_classes_combined.csv") in c
    assert any(k.startswith("addr_tx") and v < 1 for k, v in r["id_compatibility"]["tx_id_coverage"].items() if v is not None)
    assert (out / "audit" / "audit_report.md").exists()
    assert r["wallet_leakage"]["addresses_in_multiple_time_steps"] >= 1


@pytest.mark.parametrize("fmt", ["csv"])
def test_preprocess_end_to_end(fx, fmt, tmp_path):
    raw, out, info = fx
    cfg = tmp_path / "lm.json"
    cfg.write_text(json.dumps({"confirmed": False, "tx_classes": {"1": "illicit", "2": "licit", "3": "unknown"},
                               "wallet_classes": {"1": "illicit", "2": "licit", "3": "unknown"}}))
    before = sha(raw)
    Preprocessor(raw, out, fmt, chunksize=4, label_map_path=cfg).run(STEPS)
    assert sha(raw) == before
    tx = pd.read_csv(out / "tx_features.csv")
    assert len(tx) == 12 and tx["tx_id"].is_unique                       # 14 raw rows, 2 duplicates removed
    assert tx["label"].isna().all() and not tx["label_is_known"].any()   # labels unconfirmed -> no words
    assert pd.isna(tx.loc[tx.tx_id == 105, "class_raw"]).all()           # conflicting class not guessed
    assert tx["fees"].isna().sum() == 1                                  # inf -> NaN, not invented
    q = pd.read_csv(out / "quarantine" / "tx_features.csv")
    assert set(q["reason"]) == {"duplicate_tx_id"} and len(q) == 2
    idx = pd.read_csv(out / "address_index.csv")
    assert idx["address"].is_unique and not idx["address"].str.endswith(" ").any()
    w = pd.read_csv(out / "wallet_features.csv")
    assert len(w) == 7 and not w.duplicated(["addr_id", "time_step"]).any()
    ae = pd.read_csv(out / "addr_edges.csv")
    a0, a1 = [idx.loc[idx.address == info["addresses"][i], "addr_id"].iloc[0] for i in (0, 1)]
    assert ae[(ae.src_id == a0) & (ae.dst_id == a1)]["n_occurrences"].iloc[0] == 2
    assert ae["is_self_loop"].sum() == 1
    te = pd.read_csv(out / "tx_edges.csv")
    assert te["cross_time_step"].sum() == 1 and te["is_self_loop"].sum() == 1
    man = json.loads((out / "_manifest.json").read_text())
    assert man["meta"]["labels_confirmed"] is False and set(man["steps"]) == set(STEPS)


def test_confirmed_label_map_applies_words(fx, tmp_path):
    raw, out, _ = fx
    cfg = tmp_path / "lm.json"
    cfg.write_text(json.dumps({"confirmed": True, "tx_classes": {"1": "illicit", "2": "licit", "3": "unknown"},
                               "wallet_classes": {"1": "illicit", "2": "licit", "3": "unknown"}}))
    Preprocessor(raw, out, "csv", chunksize=50, label_map_path=cfg).run(["index", "tx"])
    tx = pd.read_csv(out / "tx_features.csv")
    assert set(tx["label"].dropna()) <= {"illicit", "licit", "unknown"}
    assert tx.loc[tx.label == "unknown", "label_is_known"].eq(False).all()
