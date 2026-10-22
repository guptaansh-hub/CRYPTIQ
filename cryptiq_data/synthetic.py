"""SYNTHETIC test fixtures. NOT real data. Addresses are random strings, labels are made up.
They only exist to exercise the code paths (including deliberate defects) with the
exact column layout from CRYPTIQ_schema_report.txt. Never report results from them."""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from .schema import TXS_FEATURES_COLS, WALLET_COMBINED_COLS, WALLET_FEATURE_COLS

B58 = list("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
BECH = list("qpzry9x8gf2tvdwe0s3jn54khce6mua7l")


def build_fixture(dst, seed: int = 7) -> dict:
    dst = Path(dst)
    dst.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)
    ra = lambda p: p + "".join(rng.choice(B58, 33))  # noqa: E731
    A = [ra("1") for _ in range(7)] + [ra("3") for _ in range(2)] + ["bc1q" + "".join(rng.choice(BECH, 38))]

    # ---- transactions (12 ids, steps 1-3) with defects
    ids = list(range(101, 113))
    steps = [1, 1, 1, 2, 2, 2, 3, 3, 3, 3, 3, 3]
    tf = pd.DataFrame(rng.normal(size=(12, len(TXS_FEATURES_COLS))), columns=TXS_FEATURES_COLS)
    tf["txId"], tf["Time step"] = ids, steps
    tf.loc[1, "fees"] = np.inf                     # non-finite
    tf.loc[2, "Local_feature_5"] = np.nan          # missing
    dup_same = tf.iloc[[2]].copy()                 # exact duplicate of 103
    dup_conf = tf.iloc[[3]].copy()                 # conflicting duplicate of 104
    dup_conf["Local_feature_1"] += 1
    tf = pd.concat([tf, dup_same, dup_conf], ignore_index=True)
    tf.to_csv(dst / "txs_features.csv", index=False)

    pd.DataFrame({"txId": ids[:10] + [105, 999], "class": [1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3]}
                 ).to_csv(dst / "txs_classes.csv", index=False)   # 105 has classes 2 and 2? see below
    cl = pd.read_csv(dst / "txs_classes.csv")
    cl.loc[cl.index[-2], "class"] = 1              # 105 now appears with class 2 and 1 -> conflict
    cl.to_csv(dst / "txs_classes.csv", index=False)
    pd.DataFrame({"txId1": [101, 102, 103, 103, 105, 101], "txId2": [102, 103, 103, 106, 999, 102]}
                 ).to_csv(dst / "txs_edgelist.csv", index=False)

    # ---- address graph files (with whitespace, duplicate, null, invalid, self loop)
    pd.DataFrame({"input_address": [A[0], A[0], A[1], A[0], A[9], A[2]],
                  "output_address": [A[1], A[0], A[2], A[1], "not_an_address", A[3]]}
                 ).to_csv(dst / "AddrAddr_edgelist.csv", index=False)
    pd.DataFrame({"input_address": [A[0], A[1], A[2], A[0] + " ", A[3]], "txId": [101, 102, 103, 104, 999]}
                 ).to_csv(dst / "AddrTx_edgelist.csv", index=False)
    pd.DataFrame({"txId": [101, 101, 102, 103, 103, 104], "output_address": [A[1], A[0], A[2], A[3], A[3], ""]}
                 ).to_csv(dst / "TxAddr_edgelist.csv", index=False)

    # ---- wallets: A0 in steps 1-3 (whole-history style columns), A1 one row claiming 2 steps
    rows = []
    def w(addr, step, first, last, nts, total):
        r = dict.fromkeys(WALLET_FEATURE_COLS, 0.0)
        r.update({c: float(abs(rng.normal())) for c in WALLET_FEATURE_COLS[11:]})
        r.update({"address": addr, "Time step": step, "first_block_appeared_in": first,
                  "last_block_appeared_in": last, "lifetime_in_blocks": last - first,
                  "num_timesteps_appeared_in": nts, "total_txs": total})
        rows.append(r)
    for s in (1, 2, 3):
        w(A[0], s, 1000, 9000, 3, 9)              # same whole-history values at every step -> leakage signature
    w(A[1], 2, 3000, 8000, 2, 4)                  # claims 2 steps, only 1 row present
    w(A[2], 1, 1100, 1100, 1, 1)
    w(A[2], 1, 1100, 1100, 1, 1)                  # duplicate (address, step)
    w(A[3], 3, 7000, 7000, 1, 1)
    w(A[4], 2, 4000, 4000, 1, 1)
    wf = pd.DataFrame(rows)[WALLET_FEATURE_COLS]
    wf.loc[4, "fees_total"] = np.nan
    wf.to_csv(dst / "wallets_features.csv", index=False)
    wc = pd.DataFrame({"address": [A[0], A[1], A[2], A[3], A[3], A[4], A[8]], "class": [1, 2, 3, 1, 2, 3, 2]})
    wc.to_csv(dst / "wallets_classes.csv", index=False)
    comb = wf.merge(wc.drop_duplicates("address", keep="first"), on="address", how="left")
    comb["class"] = comb["class"].fillna(3).astype(int)
    comb.loc[0, "class"] = 2                       # disagrees with wallets_classes
    comb[WALLET_COMBINED_COLS].to_csv(dst / "wallets_features_classes_combined.csv", index=False)
    return {"addresses": A}
