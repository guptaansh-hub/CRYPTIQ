"""Cleaning pipeline. Raw CSVs are read-only; outputs go to a separate folder.

Principles
- No fitted transforms here (no scaling, no imputation): those must be fitted on the
  training split only, inside the training pipeline, otherwise they leak.
- Nothing is silently dropped: duplicates / null keys / label conflicts go to
  <out>/quarantine/ and are counted in _manifest.json.
- Original identifiers survive: addresses are only whitespace-stripped (base58 is never
  case-folded) and raw class codes are kept in class_raw.
- Labels are only translated to words if config/label_map.json has confirmed=true.
"""
from __future__ import annotations

import json
import logging
import platform
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from .io_utils import (AddressIndex, CountAcc, RawGuard, TableSink, clean_address, column_map,
                       classify_address, default_format, iter_csv, read_header, read_table, sha256_file)
from .schema import EXPECTED_FILES, is_anonymised_tx_feature

LOG = logging.getLogger("cryptiq")
STEPS = ["index", "tx", "tx_edges", "wallets", "addr_edges", "bipartite"]


class Preprocessor:
    def __init__(self, raw_dir, out_dir, fmt=None, chunksize=250_000, sample_rows=None,
                 label_map_path="config/label_map.json", lock_raw=False, hash_raw=False):
        self.guard = RawGuard(raw_dir, out_dir)
        self.raw, self.out = self.guard.raw, self.guard.out
        self.out.mkdir(parents=True, exist_ok=True)
        self.fmt = fmt or default_format()
        self.chunksize, self.nrows = chunksize, sample_rows
        self.hash_raw = hash_raw
        lm = json.loads(Path(label_map_path).read_text(encoding="utf-8")) if Path(label_map_path).exists() else {}
        self.labels_confirmed = bool(lm.get("confirmed", False))
        self.label_maps = {k: {int(a): b for a, b in lm.get(k, {}).items()} for k in ("tx_classes", "wallet_classes")}
        if not self.labels_confirmed:
            LOG.warning("label_map.json confirmed=false -> `label` stays empty, only class_raw is written")
        self.manifest_path = self.out / "_manifest.json"
        self.manifest = json.loads(self.manifest_path.read_text()) if self.manifest_path.exists() else {"steps": {}}
        if lock_raw:
            self.guard.lock()
        self.quarantine: dict[str, list[pd.DataFrame]] = {}

    # ----------------------------------------------------------- helpers
    def _sink(self, name):
        return TableSink(self.out / name, self.fmt)

    def _q(self, name, df, reason):
        if len(df):
            self.quarantine.setdefault(name, []).append(df.copy().assign(reason=reason))

    def _flush_quarantine(self):
        for name, parts in self.quarantine.items():
            s = TableSink(self.out / "quarantine" / name, self.fmt)
            for p in parts:
                s.write(p.astype({c: "object" for c in p.columns if p[c].dtype.name.startswith(("string", "str"))}))
            s.close()
        self.quarantine = {}

    def _label(self, class_raw: pd.Series, which: str):
        if not self.labels_confirmed:
            lab = pd.Series([None] * len(class_raw), index=class_raw.index, dtype="object")
        else:
            lab = class_raw.map(lambda v: self.label_maps[which].get(int(v)) if pd.notna(v) else None)
        known = lab.isin(["illicit", "licit"]).to_numpy()
        return lab.astype(object), known

    def _classes(self, fname, key, clean=False):
        df = pd.read_csv(self.raw / fname, encoding="utf-8-sig", nrows=self.nrows)
        df = df.rename(columns={"class": "class_raw", "txId": "tx_id"})
        if clean:
            df[key] = clean_address(df[key])
        df = df.dropna(subset=[key])
        n = df.groupby(key)["class_raw"].nunique()
        bad = set(n[n > 1].index)
        self._q(fname.replace(".csv", ""), df[df[key].isin(bad)].astype(object), "conflicting_class")
        ok = df[~df[key].isin(bad)].drop_duplicates(key)
        return ok.set_index(key)["class_raw"], len(bad)

    def _done(self, step, **info):
        self._flush_quarantine()
        self.manifest["steps"][step] = {**info, "format": self.fmt, "finished_utc": datetime.now(timezone.utc).isoformat()}
        self._write_manifest()

    def _write_manifest(self):
        self.manifest["meta"] = {"python": platform.python_version(), "pandas": pd.__version__,
                                 "labels_confirmed": self.labels_confirmed, "sampled_rows": self.nrows,
                                 "raw_files": self.guard.verify()}
        if self.hash_raw:
            self.manifest["meta"]["raw_sha256"] = {n: sha256_file(self.raw / n) for n in EXPECTED_FILES if (self.raw / n).exists()}
        self.manifest_path.write_text(json.dumps(self.manifest, indent=2, default=str), encoding="utf-8")

    # --------------------------------------------------------- step: index
    def step_index(self):
        idx = AddressIndex()
        n_changed = 0
        sources = [("wallets_classes.csv", ["address"]), ("wallets_features.csv", ["address"]),
                   ("AddrAddr_edgelist.csv", ["input_address", "output_address"]),
                   ("AddrTx_edgelist.csv", ["input_address"]), ("TxAddr_edgelist.csv", ["output_address"])]
        for fname, cols in sources:
            if not (self.raw / fname).exists():
                continue
            for ch in iter_csv(self.raw / fname, usecols=cols, dtype={c: str for c in cols},
                               chunksize=self.chunksize, nrows=self.nrows):
                for c in cols:
                    cl = clean_address(ch[c])
                    n_changed += int((cl.notna() & (cl != ch[c])).sum())
                    idx.encode(cl.dropna())
        s = self._sink("address_index")
        s.write(idx.to_frame())
        s.close()
        self._done("index", addresses=len(idx), values_changed_by_normalisation=n_changed)
        return idx

    def _load_index(self):
        df = read_table(self.out / "address_index")
        return AddressIndex(df["address"].tolist()), df["address_type"].to_numpy()

    # ------------------------------------------------------------ step: tx
    def step_tx(self):
        fname = "txs_features.csv"
        cls_map, n_conf = self._classes("txs_classes.csv", "tx_id")
        hdr = read_header(self.raw / fname)
        rename = column_map(hdr)
        feats = [rename[c] for c in hdr if c not in ("txId", "Time step")]
        f32 = [rename[c] for c in hdr if is_anonymised_tx_feature(c)]
        seen, sink = set(), self._sink("tx_features")
        stats = dict(rows_in=0, null_key=0, duplicate=0, nonfinite_to_nan=0)
        for ch in iter_csv(self.raw / fname, chunksize=self.chunksize, nrows=self.nrows):
            ch = ch.rename(columns=rename)
            stats["rows_in"] += len(ch)
            nullk = ch["tx_id"].isna() | ch["time_step"].isna()
            self._q("tx_features", ch[nullk].astype(object), "null_key")
            stats["null_key"] += int(nullk.sum())
            ch = ch[~nullk]
            dup = ch["tx_id"].duplicated(keep="first") | ch["tx_id"].isin(seen)
            self._q("tx_features", ch[dup].astype(object), "duplicate_tx_id")
            stats["duplicate"] += int(dup.sum())
            ch = ch[~dup].copy()
            seen.update(ch["tx_id"].tolist())
            a = ch[feats].to_numpy(dtype="float64")
            bad = ~np.isfinite(a) & ~np.isnan(a)
            stats["nonfinite_to_nan"] += int(bad.sum())
            ch[feats] = ch[feats].replace([np.inf, -np.inf], np.nan)
            ch[f32] = ch[f32].astype("float32")
            ch["tx_id"] = ch["tx_id"].astype("int64")
            ch["time_step"] = ch["time_step"].astype("int16")
            craw = ch["tx_id"].map(cls_map).astype("Int8")
            lab, known = self._label(craw, "tx_classes")
            meta = pd.DataFrame({"class_raw": craw, "label": lab.astype(object), "label_is_known": known}, index=ch.index)
            sink.write(pd.concat([ch[["tx_id", "time_step"]], meta, ch[feats]], axis=1))
        sink.close()
        self._done("tx", rows_out=sink.rows, tx_classes_conflicting_ids=n_conf, column_map=rename, **stats)

    # ------------------------------------------------------- step: tx_edges
    def step_tx_edges(self):
        e = pd.read_csv(self.raw / "txs_edgelist.csv", encoding="utf-8-sig", nrows=self.nrows)
        e = e.rename(columns={"txId1": "tx_id_1", "txId2": "tx_id_2"})
        nullk = e.isna().any(axis=1)
        self._q("txs_edgelist", e[nullk].astype(object), "null_key")
        e = e[~nullk].astype("int64")
        dup = e.duplicated()
        self._q("txs_edgelist", e[dup], "duplicate_edge")
        e = e[~dup].copy()
        ts = read_table(self.out / "tx_features", columns=["tx_id", "time_step"]).set_index("tx_id")["time_step"]
        e["time_step_1"], e["time_step_2"] = e["tx_id_1"].map(ts).astype("Int16"), e["tx_id_2"].map(ts).astype("Int16")
        e["endpoints_in_features"] = e["time_step_1"].notna() & e["time_step_2"].notna()
        e["cross_time_step"] = (e["time_step_1"] != e["time_step_2"]) & e["endpoints_in_features"]
        e["is_self_loop"] = e["tx_id_1"] == e["tx_id_2"]
        s = self._sink("tx_edges")
        s.write(e)
        s.close()
        self._done("tx_edges", rows_out=len(e), duplicates_removed=int(dup.sum()), null_key=int(nullk.sum()),
                   self_loops=int(e["is_self_loop"].sum()), cross_time_step=int(e["cross_time_step"].sum()),
                   endpoints_missing_in_features=int((~e["endpoints_in_features"]).sum()))

    # ------------------------------------------------------- step: wallets
    def step_wallets(self):
        idx, types = self._load_index()
        cls_map, n_conf = self._classes("wallets_classes.csv", "address", clean=True)
        fname = "wallets_features.csv"
        hdr = read_header(self.raw / fname)
        rename = column_map(hdr)
        feats = [rename[c] for c in hdr if c not in ("address", "Time step")]
        seen, sink = np.array([], dtype=np.int64), self._sink("wallet_features")
        stats = dict(rows_in=0, null_key=0, duplicate=0, nonfinite_to_nan=0)
        for ch in iter_csv(self.raw / fname, dtype={"address": str}, chunksize=self.chunksize, nrows=self.nrows):
            ch = ch.rename(columns=rename)
            stats["rows_in"] += len(ch)
            ch["address"] = clean_address(ch["address"])
            nullk = ch["address"].isna() | ch["time_step"].isna()
            self._q("wallet_features", ch[nullk].astype(object), "null_key")
            stats["null_key"] += int(nullk.sum())
            ch = ch[~nullk].copy()
            ch["addr_id"] = idx.encode(ch["address"], strict=True)
            ch["time_step"] = ch["time_step"].astype("int16")
            key = ch["addr_id"].to_numpy() * 1024 + ch["time_step"].to_numpy().astype(np.int64)
            dup = pd.Series(key).duplicated().to_numpy() | np.isin(key, seen)
            self._q("wallet_features", ch[dup].astype(object), "duplicate_address_time_step")
            stats["duplicate"] += int(dup.sum())
            seen = np.union1d(seen, key[~dup])
            ch = ch[~dup].copy()
            a = ch[feats].to_numpy(dtype="float64")
            stats["nonfinite_to_nan"] += int((~np.isfinite(a) & ~np.isnan(a)).sum())
            ch[feats] = ch[feats].replace([np.inf, -np.inf], np.nan).astype("float64")
            ch["address_type"] = types[ch["addr_id"].to_numpy()]
            ch["class_raw"] = ch["address"].map(cls_map).astype("Int8")
            lab, known = self._label(ch["class_raw"], "wallet_classes")
            ch["label"], ch["label_is_known"] = lab.astype(object), known
            ch = ch[["addr_id", "address", "address_type", "time_step", "class_raw", "label", "label_is_known"] + feats]
            sink.write(ch)
        sink.close()
        self._done("wallets", rows_out=sink.rows, wallet_classes_conflicting_addresses=n_conf, column_map=rename, **stats)

    # ------------------------------------------------------ step: addr_edges
    def step_addr_edges(self):
        idx, _ = self._load_index()
        n, acc, dropped = len(idx), CountAcc(), 0
        for ch in iter_csv(self.raw / "AddrAddr_edgelist.csv", dtype={"input_address": str, "output_address": str},
                           chunksize=self.chunksize, nrows=self.nrows):
            a, b = clean_address(ch["input_address"]), clean_address(ch["output_address"])
            ok = a.notna() & b.notna()
            dropped += int((~ok).sum())
            self._q("AddrAddr_edgelist", ch[~ok].astype(object), "null_address")
            acc.add(idx.encode(a[ok], strict=True) * n + idx.encode(b[ok], strict=True))
        keys, cnt = acc.result()
        sink = self._sink("addr_edges")
        for i in range(0, max(len(keys), 1), 2_000_000):
            k, c = keys[i:i + 2_000_000], cnt[i:i + 2_000_000]
            src, dst = k // n, k % n
            sink.write(pd.DataFrame({"src_id": src, "dst_id": dst, "n_occurrences": c, "is_self_loop": src == dst}))
        sink.close()
        self._done("addr_edges", unique_edges=len(keys), rows_in=int(cnt.sum()) + dropped, null_address_rows=dropped,
                   self_loops=int(((keys // n) == (keys % n)).sum()),
                   note="n_occurrences = number of source rows for the pair; NOT a BTC amount and not asserted to be a tx count")

    # ------------------------------------------------------- step: bipartite
    def step_bipartite(self):
        idx, _ = self._load_index()
        known = set(read_table(self.out / "tx_features", columns=["tx_id"])["tx_id"].tolist())
        info = {}
        for fname, acol, out, order in (("AddrTx_edgelist.csv", "input_address", "addr_tx_in", "addr_tx"),
                                        ("TxAddr_edgelist.csv", "output_address", "tx_addr_out", "tx_addr")):
            acc, dropped = CountAcc(), 0
            for ch in iter_csv(self.raw / fname, dtype={acol: str}, chunksize=self.chunksize, nrows=self.nrows):
                a = clean_address(ch[acol])
                ok = a.notna() & ch["txId"].notna()
                dropped += int((~ok).sum())
                self._q(fname.replace(".csv", ""), ch[~ok].astype(object), "null_key")
                tx = ch.loc[ok, "txId"].astype("int64").to_numpy()
                if len(tx) and tx.max() >= 2 ** 32:
                    raise ValueError("txId exceeds 32 bits; key packing would collide")
                acc.add(idx.encode(a[ok], strict=True) * (2 ** 32) + tx)
            keys, cnt = acc.result()
            df = pd.DataFrame({"addr_id": keys >> 32, "tx_id": keys & 0xFFFFFFFF, "n_occurrences": cnt})
            df["tx_in_features"] = df["tx_id"].isin(known)
            if order == "tx_addr":
                df = df[["tx_id", "addr_id", "n_occurrences", "tx_in_features"]]
            s = self._sink(out)
            s.write(df)
            s.close()
            info[out] = {"unique_rows": len(df), "null_key_rows": dropped, "tx_not_in_features": int((~df["tx_in_features"]).sum())}
        self._done("bipartite", **info)

    def run(self, steps):
        for st in steps:
            LOG.info("=== step: %s", st)
            getattr(self, f"step_{st}")()
        self._write_manifest()
