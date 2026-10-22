"""Chunked IO, identifier normalisation, output writers, raw-data protection."""
from __future__ import annotations

import hashlib
import logging
import os
import re
import stat
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd

LOG = logging.getLogger("cryptiq")

try:  # parquet is the default output; CSV is the fallback
    import pyarrow as pa
    import pyarrow.parquet as pq
    HAVE_PYARROW = True
except Exception:  # pragma: no cover
    HAVE_PYARROW = False

# ----------------------------------------------------------------- columns
_SPECIAL = {"txId": "tx_id", "txId1": "tx_id_1", "txId2": "tx_id_2",
            "Time step": "time_step", "class": "class_raw"}


def norm_col(name: str) -> str:
    n = name.strip()
    if n in _SPECIAL:
        return _SPECIAL[n]
    return re.sub(r"[^0-9a-zA-Z]+", "_", n).strip("_").lower()


def column_map(columns: list[str]) -> dict[str, str]:
    m = {c: norm_col(c) for c in columns}
    if len(set(m.values())) != len(m):
        raise ValueError("Column-name normalisation created a collision")
    return m


# ------------------------------------------------------------------ reading
def read_header(path: Path) -> list[str]:
    return pd.read_csv(path, nrows=0, encoding="utf-8-sig").columns.tolist()


def iter_csv(path: Path, usecols=None, dtype=None, chunksize: int = 250_000,
             nrows: int | None = None) -> Iterator[pd.DataFrame]:
    """Read-only chunked CSV iterator. utf-8-sig strips a BOM if Windows added one."""
    reader = pd.read_csv(path, usecols=usecols, dtype=dtype, chunksize=chunksize,
                         nrows=nrows, encoding="utf-8-sig")
    for i, chunk in enumerate(reader):
        if i and i % 10 == 0:
            LOG.info("  %s: %d chunks read", Path(path).name, i)
        yield chunk


# ---------------------------------------------------------------- addresses
_B58 = "[1-9A-HJ-NP-Za-km-z]"
RE_P2PKH = rf"^1{_B58}{{25,33}}$"
RE_P2SH = rf"^3{_B58}{{25,33}}$"
RE_BECH32 = r"^bc1q[02-9ac-hj-np-z]{38,58}$"
RE_TAPROOT = r"^bc1p[02-9ac-hj-np-z]{58}$"
ADDRESS_TYPES = ["p2pkh", "p2sh", "bech32_segwit_v0", "bech32m_taproot",
                 "other_or_invalid", "missing"]


def clean_address(s: pd.Series) -> pd.Series:
    """Strip whitespace; lower-case ONLY fully upper-case bech32. Base58 is
    case-sensitive and is never case-folded. Empty -> missing. No checksum check."""
    x = pd.Series(s.to_numpy(dtype=object), index=s.index, dtype="object")
    x = x.map(lambda v: v.strip() if isinstance(v, str) else None)
    x = x.map(lambda v: v.lower() if isinstance(v, str) and re.fullmatch(r"BC1[0-9A-Z]+", v) else v)
    x = x.map(lambda v: None if v == "" else v)
    return x


def classify_address(s: pd.Series) -> pd.Series:
    x = pd.Series([v if isinstance(v, str) else "" for v in s.to_numpy(dtype=object)],
                  index=s.index, dtype="object")
    conds = [x.str.match(RE_P2PKH).to_numpy(dtype=bool), x.str.match(RE_P2SH).to_numpy(dtype=bool),
             x.str.match(RE_BECH32).to_numpy(dtype=bool), x.str.match(RE_TAPROOT).to_numpy(dtype=bool),
             (x == "").to_numpy(dtype=bool)]
    out = np.select(conds, ["p2pkh", "p2sh", "bech32_segwit_v0", "bech32m_taproot", "missing"],
                    default="other_or_invalid")
    return pd.Series(out, index=s.index)


class AddressIndex:
    """Stable address -> int64 id map (ids follow first-appearance order)."""

    def __init__(self, addresses=None):
        self.index = pd.Index(addresses if addresses is not None else [], dtype=object)

    def __len__(self) -> int:
        return len(self.index)

    def encode(self, s: pd.Series, strict: bool = False) -> np.ndarray:
        vals = s.to_numpy(dtype=object)
        pos = self.index.get_indexer(vals)
        miss = pos < 0
        if miss.any():
            if strict:
                raise KeyError(f"{int(miss.sum())} addresses missing from address_index")
            new = pd.unique(vals[miss])
            self.index = self.index.append(pd.Index(new, dtype=object))
            pos = self.index.get_indexer(vals)
        return pos.astype(np.int64)

    def to_frame(self) -> pd.DataFrame:
        addr = pd.Series(self.index.to_numpy(dtype=object), dtype="object")
        return pd.DataFrame({"addr_id": np.arange(len(addr), dtype=np.int64),
                             "address": addr.astype(str),
                             "address_type": classify_address(addr).astype(str).to_numpy()})


# ---------------------------------------------------------------- hashing
def row_hash(df: pd.DataFrame) -> np.ndarray:
    return pd.util.hash_pandas_object(df, index=False).to_numpy()


class UniqueAcc:
    """Accumulates unique uint64 values across chunks."""

    def __init__(self):
        self.arr = np.array([], dtype=np.uint64)

    def add(self, a: np.ndarray):
        if len(a):
            self.arr = np.union1d(self.arr, a.astype(np.uint64, copy=False))

    def __len__(self):
        return len(self.arr)


class CountAcc:
    """Accumulates (key -> count) for int64 keys without a Python dict."""

    def __init__(self, merge_every: int = 8):
        self.keys = np.array([], dtype=np.int64)
        self.cnts = np.array([], dtype=np.int64)
        self.pending = []
        self.merge_every = merge_every

    def add(self, keys: np.ndarray):
        k, c = np.unique(keys, return_counts=True)
        self.pending.append((k, c))
        if len(self.pending) >= self.merge_every:
            self._merge()

    def _merge(self):
        if not self.pending:
            return
        ks = np.concatenate([self.keys] + [p[0] for p in self.pending])
        cs = np.concatenate([self.cnts] + [p[1] for p in self.pending])
        uk, inv = np.unique(ks, return_inverse=True)
        self.keys = uk
        self.cnts = np.bincount(inv.ravel(), weights=cs).astype(np.int64)
        self.pending = []

    def result(self):
        self._merge()
        return self.keys, self.cnts


# ------------------------------------------------------------------ output
def default_format() -> str:
    return "parquet" if HAVE_PYARROW else "csv"


class TableSink:
    """Appends DataFrame chunks to parquet (default) or csv; atomic on close."""

    def __init__(self, base: Path, fmt: str):
        if fmt == "parquet" and not HAVE_PYARROW:
            raise RuntimeError("pyarrow not installed; use --format csv or pip install pyarrow")
        self.fmt = fmt
        self.path = Path(str(base) + (".parquet" if fmt == "parquet" else ".csv"))
        self.tmp = self.path.with_name(self.path.name + ".tmp")
        self.tmp.parent.mkdir(parents=True, exist_ok=True)
        self.rows = 0
        self._writer = None
        self._schema = None
        self._wrote_header = False
        if self.tmp.exists():
            self.tmp.unlink()

    def write(self, df: pd.DataFrame):
        if df.empty and self._schema is not None:
            return
        if self.fmt == "parquet":
            t = pa.Table.from_pandas(df, preserve_index=False)
            if self._writer is None:
                self._schema = t.schema
                self._writer = pq.ParquetWriter(self.tmp, self._schema, compression="zstd")
            else:
                t = t.cast(self._schema)
            self._writer.write_table(t)
        else:
            df.to_csv(self.tmp, mode="a", header=not self._wrote_header, index=False)
            self._wrote_header = True
            self._schema = True
        self.rows += len(df)

    def close(self) -> Path:
        if self._writer is not None:
            self._writer.close()
        if self._schema is None:
            self.tmp.write_bytes(b"")
        os.replace(self.tmp, self.path)
        return self.path


def read_table(base: Path, columns=None) -> pd.DataFrame:
    for ext in (".parquet", ".csv"):
        p = Path(str(base) + ext)
        if p.exists():
            if ext == ".parquet":
                return pd.read_parquet(p, columns=columns)
            return pd.read_csv(p, usecols=columns)
    raise FileNotFoundError(f"{base}.parquet/.csv not found - run the earlier step first")


# ---------------------------------------------------------- raw protection
def sha256_file(path: Path, block: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(block):
            h.update(chunk)
    return h.hexdigest()


class RawGuard:
    """Raw files are only ever opened for reading. This guard (1) refuses an
    output dir inside the raw dir, (2) snapshots size+mtime and verifies them
    unchanged afterwards, (3) optionally marks files read-only."""

    def __init__(self, raw_dir, out_dir):
        self.raw = Path(raw_dir).resolve()
        self.out = Path(out_dir).resolve()
        if self.out == self.raw or self.raw in self.out.parents:
            raise ValueError("Output directory must be OUTSIDE the raw data directory")
        self.before = self._snap()

    def _snap(self):
        return {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in sorted(self.raw.glob("*.csv"))}

    def lock(self):
        for p in self.raw.glob("*.csv"):
            os.chmod(p, stat.S_IREAD)  # on Windows this sets the read-only attribute

    def verify(self):
        after = self._snap()
        if after != self.before:
            raise RuntimeError("RAW FILES CHANGED during the run - aborting")
        return {k: {"bytes": v[0]} for k, v in after.items()}
