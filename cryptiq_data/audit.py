"""Read-only data audit. Never writes into the raw directory.

Everything reported here is *measured* from the files. Hash-based duplicate and
overlap counts use 64-bit hashes (collision probability negligible at this size,
but they are technically approximate; the report says so).
"""
from __future__ import annotations

import json
import logging
import platform
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from .io_utils import (RawGuard, UniqueAcc, classify_address, clean_address, iter_csv,
                       read_header, row_hash)
from .schema import ADDRESS_COLS, EXPECTED_FILES, TX_ID_COLS, is_nonnegative_expected

LOG = logging.getLogger("cryptiq")


class Findings:
    def __init__(self):
        self.items: list[dict] = []

    def add(self, level: str, code: str, file: str, message: str):
        self.items.append({"level": level, "code": code, "file": file, "message": message})
        LOG.info("[%s] %s %s: %s", level, code, file, message)


def _py(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return None if np.isnan(o) else float(o)
    if isinstance(o, dict):
        return {str(k): _py(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_py(v) for v in o]
    return o


def _hash_addr(cleaned: pd.Series) -> np.ndarray:
    return pd.util.hash_pandas_object(cleaned.dropna().astype(str), index=False).to_numpy()


# ------------------------------------------------------------------ headers
def audit_headers(raw: Path, F: Findings) -> dict:
    out = {}
    for name, (kind, expected) in EXPECTED_FILES.items():
        p = raw / name
        if not p.exists():
            F.add("CRITICAL" if kind != "wallet_combined" else "WARN", "MISSING_FILE", name, "file not found")
            out[name] = {"present": False}
            continue
        cols = read_header(p)
        miss, extra = [c for c in expected if c not in cols], [c for c in cols if c not in expected]
        out[name] = {"present": True, "bytes": p.stat().st_size, "n_columns": len(cols),
                     "missing_columns": miss, "unexpected_columns": extra}
        if miss or extra:
            F.add("CRITICAL", "SCHEMA_MISMATCH", name, f"missing={miss[:5]} unexpected={extra[:5]}")
    return out


# ------------------------------------------------------------------ profile
def profile_file(raw: Path, name: str, key_cols: list[str], chunksize: int, nrows, F: Findings,
                 self_loop: tuple[str, str] | None = None):
    kind, _ = EXPECTED_FILES[name]
    rows = 0
    nulls, infs, neg = Counter(), Counter(), Counter()
    mins, maxs = {}, {}
    non_numeric: set[str] = set()
    key_h, row_h = [], []
    ids = {c: UniqueAcc() for c in ADDRESS_COLS | TX_ID_COLS}
    fmt = {c: Counter() for c in ADDRESS_COLS}
    ws = Counter()
    n_self = 0
    for chunk in iter_csv(raw / name, chunksize=chunksize, nrows=nrows):
        rows += len(chunk)
        nulls.update(chunk.isna().sum()[lambda s: s > 0].to_dict())
        work = chunk.copy()
        for c in chunk.columns:
            if c in ADDRESS_COLS:
                raw_s = chunk[c]
                ws[c] += int((raw_s.notna() & (raw_s.astype(str) != raw_s.astype(str).str.strip())).sum())
                cl = clean_address(raw_s)
                work[c] = cl
                fmt[c].update(classify_address(cl).value_counts().to_dict())
                ids[c].add(_hash_addr(cl))
            elif c in TX_ID_COLS:
                ids[c].add(chunk[c].dropna().to_numpy())
        num = chunk.select_dtypes("number")
        for c in chunk.columns:
            if c not in ADDRESS_COLS and c not in num.columns:
                non_numeric.add(c)
        if len(num.columns):
            a = num.to_numpy(dtype="float64")
            inf_ct = np.isinf(a).sum(axis=0)
            for c, v in zip(num.columns, inf_ct):
                if v:
                    infs[c] += int(v)
            mn, mx = num.min(), num.max()
            for c in num.columns:
                mins[c] = min(mins.get(c, np.inf), mn[c]) if pd.notna(mn[c]) else mins.get(c, np.inf)
                maxs[c] = max(maxs.get(c, -np.inf), mx[c]) if pd.notna(mx[c]) else maxs.get(c, -np.inf)
                if is_nonnegative_expected(kind, c):
                    neg[c] += int((num[c] < 0).sum())
        key_h.append(row_hash(work[key_cols]))
        row_h.append(row_hash(work))
        if self_loop:
            n_self += int((work[self_loop[0]].notna() & (work[self_loop[0]] == work[self_loop[1]])).sum())
    kh, rh = np.concatenate(key_h), np.concatenate(row_h)
    dup_keys = rows - len(np.unique(kh))
    dup_rows = rows - len(np.unique(rh))
    const = [c for c in mins if mins[c] == maxs.get(c)]
    summ = {"rows": rows, "null_counts": dict(nulls), "inf_counts": dict(infs),
            "negative_in_nonneg_cols": {k: v for k, v in neg.items() if v},
            "non_numeric_columns": sorted(non_numeric), "constant_columns": const,
            "duplicate_keys": dup_keys, "duplicate_full_rows": dup_rows, "key": key_cols,
            "address_formats": {c: dict(v) for c, v in fmt.items() if v},
            "addresses_with_surrounding_whitespace": {c: v for c, v in ws.items() if v},
            "self_loops": n_self if self_loop else None}
    if nrows:
        F.add("WARN", "SAMPLED", name, f"only first {nrows} rows were read; counts are NOT full-file")
    if dup_keys:
        lvl = "WARN"
        F.add(lvl, "DUPLICATE_KEYS", name, f"{dup_keys} rows repeat an earlier key {key_cols} "
              f"({dup_rows} are exact full-row duplicates; the rest conflict)")
    if nulls:
        F.add("WARN", "NULLS", name, f"{len(nulls)} columns have missing values, e.g. {dict(list(nulls.items())[:3])}")
    if infs:
        F.add("WARN", "NONFINITE", name, f"infinite values in {dict(list(infs.items())[:3])}")
    if summ["negative_in_nonneg_cols"]:
        F.add("WARN", "NEGATIVE_VALUES", name, f"negatives in {list(summ['negative_in_nonneg_cols'])[:5]}")
    if non_numeric:
        F.add("CRITICAL", "NON_NUMERIC", name, f"expected numeric but got text: {sorted(non_numeric)[:5]}")
    if summ["addresses_with_surrounding_whitespace"]:
        F.add("WARN", "ADDRESS_WHITESPACE", name, f"{summ['addresses_with_surrounding_whitespace']}")
    bad = {c: v.get("other_or_invalid", 0) + v.get("missing", 0) for c, v in fmt.items() if v}
    if any(bad.values()):
        F.add("WARN", "ADDRESS_FORMAT", name, f"addresses not matching a known Bitcoin format (format check only, no checksum): {bad}")
    if self_loop and n_self:
        F.add("INFO", "SELF_LOOPS", name, f"{n_self} rows have identical source and target (often change outputs)")
    return summ, {c: a.arr for c, a in ids.items() if len(a)}


def _cover(a: np.ndarray, b: np.ndarray):
    if a is None or b is None or len(a) == 0:
        return None
    return round(float(np.isin(a, b).mean()), 6)


# ------------------------------------------------------------- cross checks
def audit_ids(ids: dict, F: Findings) -> dict:
    g = lambda f, c: ids.get(f, {}).get(c)  # noqa: E731
    tx = {"features": g("txs_features.csv", "txId"), "classes": g("txs_classes.csv", "txId"),
          "tx_edges_1": g("txs_edgelist.csv", "txId1"), "tx_edges_2": g("txs_edgelist.csv", "txId2"),
          "addr_tx": g("AddrTx_edgelist.csv", "txId"), "tx_addr": g("TxAddr_edgelist.csv", "txId")}
    res = {"tx_id_unique_counts": {k: (None if v is None else int(len(v))) for k, v in tx.items()}, "tx_id_coverage": {}}
    for k in ("classes", "tx_edges_1", "tx_edges_2", "addr_tx", "tx_addr"):
        res["tx_id_coverage"][f"{k}_in_features"] = _cover(tx[k], tx["features"])
        c = res["tx_id_coverage"][f"{k}_in_features"]
        if c is not None and c < 1:
            F.add("WARN", "ID_COVERAGE", k, f"only {c:.2%} of {k} txIds exist in txs_features")
    res["tx_id_coverage"]["features_in_classes"] = _cover(tx["features"], tx["classes"])
    ad = {"wallet_features": g("wallets_features.csv", "address"), "wallet_classes": g("wallets_classes.csv", "address"),
          "addr_addr_in": g("AddrAddr_edgelist.csv", "input_address"), "addr_addr_out": g("AddrAddr_edgelist.csv", "output_address"),
          "addr_tx_in": g("AddrTx_edgelist.csv", "input_address"), "tx_addr_out": g("TxAddr_edgelist.csv", "output_address")}
    res["address_unique_counts"] = {k: (None if v is None else int(len(v))) for k, v in ad.items()}
    res["address_coverage"] = {}
    for a, b in [("wallet_classes", "wallet_features"), ("wallet_features", "wallet_classes"),
                 ("addr_tx_in", "wallet_features"), ("tx_addr_out", "wallet_features"),
                 ("addr_addr_in", "wallet_features"), ("addr_addr_out", "wallet_features")]:
        c = _cover(ad[a], ad[b])
        res["address_coverage"][f"{a}_in_{b}"] = c
        if c is not None and c < 1 and a != "wallet_features":
            F.add("INFO", "ID_COVERAGE", a, f"{c:.2%} of {a} addresses appear in {b}")
    F.add("INFO", "TXID_IS_DATASET_ID", "txs_*", "txId is the dataset's own integer id; the files contain no Bitcoin "
          "transaction hash column, so these transactions cannot be looked up on a live explorer from this data alone")
    return res


# ----------------------------------------------------------------- labels
def audit_labels(raw: Path, F: Findings, nrows) -> dict:
    out = {}
    for name, key in (("txs_classes.csv", "txId"), ("wallets_classes.csv", "address")):
        p = raw / name
        if not p.exists():
            continue
        df = pd.read_csv(p, encoding="utf-8-sig", nrows=nrows)
        if key == "address":
            df[key] = clean_address(df[key])
        vc = df["class"].value_counts(dropna=False).sort_index()
        n = df.groupby(key)["class"].nunique()
        conflicts = int((n > 1).sum())
        out[name] = {"class_counts": {str(k): int(v) for k, v in vc.items()}, "keys_with_conflicting_classes": conflicts}
        F.add("INFO", "CLASS_VALUES", name, f"raw class counts {out[name]['class_counts']} (meaning NOT assumed; see config/label_map.json)")
        if conflicts:
            F.add("WARN", "LABEL_CONFLICT", name, f"{conflicts} keys carry more than one class")
    return out


def audit_combined_vs_classes(raw: Path, chunksize, nrows, F: Findings) -> dict:
    pc, pm = raw / "wallets_classes.csv", raw / "wallets_features_classes_combined.csv"
    if not (pc.exists() and pm.exists()):
        return {}
    cls = pd.read_csv(pc, encoding="utf-8-sig")
    cls["address"] = clean_address(cls["address"])
    cmap = cls.drop_duplicates("address", keep=False).set_index("address")["class"]
    mismatch = absent = rows = 0
    per_step = Counter()
    for ch in iter_csv(pm, usecols=["address", "Time step", "class"], chunksize=chunksize, nrows=nrows):
        a = clean_address(ch["address"])
        ref = a.map(cmap)
        rows += len(ch)
        absent += int(ref.isna().sum())
        mismatch += int(((ref.notna()) & (ref != ch["class"])).sum())
        for (t, c), n in ch.groupby(["Time step", "class"]).size().items():
            per_step[(int(t), int(c))] += int(n)
    if mismatch:
        F.add("WARN", "COMBINED_MISMATCH", "wallets_features_classes_combined.csv",
              f"{mismatch} rows disagree with wallets_classes.csv")
    table = {}
    for (t, c), n in per_step.items():
        table.setdefault(t, {})[str(c)] = n
    return {"rows": rows, "class_disagrees_with_wallets_classes": mismatch,
            "address_not_in_unambiguous_wallets_classes": absent, "class_counts_by_time_step": dict(sorted(table.items()))}


# ------------------------------------------------------------- graph/time
def audit_graph(raw: Path, chunksize, nrows, F: Findings) -> dict:
    pf, pe = raw / "txs_features.csv", raw / "txs_edgelist.csv"
    if not (pf.exists() and pe.exists()):
        return {}
    ts = pd.read_csv(pf, usecols=["txId", "Time step"], encoding="utf-8-sig", nrows=nrows)
    ts = ts.drop_duplicates("txId").set_index("txId")["Time step"]
    e = pd.read_csv(pe, encoding="utf-8-sig", nrows=nrows)
    a, b = e["txId1"].map(ts), e["txId2"].map(ts)
    both = a.notna() & b.notna()
    cross = int((both & (a != b)).sum())
    res = {"edges": len(e), "edges_with_both_endpoints_in_features": int(both.sum()),
           "edges_crossing_time_steps": cross, "time_steps": [int(ts.min()), int(ts.max())] if len(ts) else None}
    if cross:
        F.add("WARN", "CROSS_TIMESTEP_EDGES", "txs_edgelist.csv", f"{cross} edges connect different time steps")
    else:
        F.add("INFO", "GRAPH_PER_TIMESTEP", "txs_edgelist.csv", "no edge crosses time steps (graph is a set of per-time-step graphs)")
    pc = raw / "txs_classes.csv"
    if pc.exists():
        c = pd.read_csv(pc, encoding="utf-8-sig", nrows=nrows).drop_duplicates("txId", keep=False).set_index("txId")["class"]
        d = pd.DataFrame({"ts": ts, "cls": c}).dropna()
        res["tx_class_counts_by_time_step"] = {int(t): {str(k): int(v) for k, v in g["cls"].value_counts().items()}
                                               for t, g in d.groupby("ts")}
    return res


# ---------------------------------------------------------------- leakage
def audit_wallet_leakage(raw: Path, chunksize, nrows, F: Findings) -> dict:
    p = raw / "wallets_features.csv"
    if not p.exists():
        return {}
    cols = ["address", "Time step", "first_block_appeared_in", "last_block_appeared_in",
            "lifetime_in_blocks", "total_txs", "num_timesteps_appeared_in"]
    parts = []
    for ch in iter_csv(p, usecols=cols, chunksize=chunksize, nrows=nrows):
        h = pd.util.hash_pandas_object(clean_address(ch["address"]).astype(str), index=False).to_numpy()
        d = ch.drop(columns="address")
        d.insert(0, "a", h)
        parts.append(d)
    d = pd.concat(parts, ignore_index=True).sort_values(["a", "Time step"], kind="stable")
    k = d.groupby("a").cumcount() + 1
    size = d.groupby("a")["a"].transform("size")
    nts = d["num_timesteps_appeared_in"]
    n_addr, n_rows = d["a"].nunique(), len(d)
    multi = size > 1
    res = {"rows": n_rows, "unique_addresses": int(n_addr),
           "addresses_in_multiple_time_steps": int(d.loc[multi, "a"].nunique()),
           "rows_where_num_timesteps_exceeds_this_rows_ordinal": int((nts > k).sum()),
           "rows_where_num_timesteps_exceeds_rows_present_for_address": int((nts > size).sum()),
           "rows_where_last_block_minus_first_block_ne_lifetime": int(
               ((d["last_block_appeared_in"] - d["first_block_appeared_in"]) != d["lifetime_in_blocks"]).sum())}
    if multi.any():
        const = d[multi].groupby("a")["last_block_appeared_in"].nunique().eq(1).mean()
        res["share_multi_step_addresses_with_constant_last_block"] = round(float(const), 6)
    fut = res["rows_where_num_timesteps_exceeds_this_rows_ordinal"]
    if fut:
        F.add("CRITICAL", "LEAKAGE_WHOLE_HISTORY", "wallets_features.csv",
              f"{fut}/{n_rows} rows report num_timesteps_appeared_in larger than the number of time steps seen "
              "up to that row -> these columns look like whole-history summaries, i.e. they contain FUTURE "
              "information relative to the row's Time step. Temporal evaluation on them will be optimistic.")
    if res["addresses_in_multiple_time_steps"]:
        F.add("WARN", "LEAKAGE_ADDRESS_REPEATS", "wallets_features.csv",
              f"{res['addresses_in_multiple_time_steps']} addresses occur in several time steps; a random row split "
              "would put the same (labelled) address in train and test. Split by time step and group by address.")
    return res


# -------------------------------------------------------------------- main
def run_audit(raw_dir, out_dir, chunksize: int = 250_000, sample_rows: int | None = None) -> dict:
    guard = RawGuard(raw_dir, out_dir)
    raw, out = guard.raw, guard.out
    (out / "audit").mkdir(parents=True, exist_ok=True)
    F = Findings()
    report = {"meta": {"created_utc": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
                       "pandas": pd.__version__, "sampled_rows": sample_rows,
                       "note": "hash-based counts use 64-bit hashes (approximate in theory, exact in practice)"}}
    report["headers"] = audit_headers(raw, F)
    keys = {"txs_features.csv": ["txId"], "txs_classes.csv": ["txId"], "txs_edgelist.csv": ["txId1", "txId2"],
            "wallets_classes.csv": ["address"], "wallets_features.csv": ["address", "Time step"],
            "wallets_features_classes_combined.csv": ["address", "Time step"],
            "AddrAddr_edgelist.csv": ["input_address", "output_address"],
            "AddrTx_edgelist.csv": ["input_address", "txId"], "TxAddr_edgelist.csv": ["txId", "output_address"]}
    loops = {"AddrAddr_edgelist.csv": ("input_address", "output_address"), "txs_edgelist.csv": ("txId1", "txId2")}
    report["files"], ids = {}, {}
    for name, key in keys.items():
        if not (raw / name).exists() or report["headers"][name].get("missing_columns"):
            continue
        LOG.info("Profiling %s", name)
        report["files"][name], ids[name] = profile_file(raw, name, key, chunksize, sample_rows, F, loops.get(name))
    report["id_compatibility"] = audit_ids(ids, F)
    report["labels"] = audit_labels(raw, F, sample_rows)
    report["combined_vs_classes"] = audit_combined_vs_classes(raw, chunksize, sample_rows, F)
    report["graph_and_time"] = audit_graph(raw, chunksize, sample_rows, F)
    report["wallet_leakage"] = audit_wallet_leakage(raw, chunksize, sample_rows, F)
    report["findings"] = F.items
    report["raw_files_unchanged"] = guard.verify()
    (out / "audit" / "audit_report.json").write_text(json.dumps(_py(report), indent=2), encoding="utf-8")
    (out / "audit" / "audit_report.md").write_text(render_markdown(report), encoding="utf-8")
    return report


def render_markdown(r: dict) -> str:
    L = ["# CRYPTIQ data audit", "", f"Created: {r['meta']['created_utc']}  |  sampled rows: {r['meta']['sampled_rows']}", "",
         "## Findings", "", "| Level | Code | File | Message |", "|---|---|---|---|"]
    order = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
    for f in sorted(r["findings"], key=lambda x: order[x["level"]]):
        L.append(f"| {f['level']} | {f['code']} | {f['file']} | {f['message'].replace('|', '/')} |")
    L += ["", "## Per-file summary", "", "| File | Rows | Dup keys | Dup full rows | Cols with nulls |", "|---|---|---|---|---|"]
    for n, s in r["files"].items():
        L.append(f"| {n} | {s['rows']} | {s['duplicate_keys']} | {s['duplicate_full_rows']} | {len(s['null_counts'])} |")
    L += ["", "## Details (JSON)", "", "See `audit_report.json` for ID coverage, label counts, graph/time and leakage numbers."]
    return "\n".join(L) + "\n"
