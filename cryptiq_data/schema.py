"""Expected schemas, taken from CRYPTIQ_schema_report.txt (the user's own export).

Nothing here is assumed about the *values*; only column names/roles that the
schema report shows. Value semantics (e.g. what class 1/2/3 mean) live in
config/label_map.json and must be confirmed by a human.
"""
from __future__ import annotations

STATS = ["total", "min", "max", "mean", "median"]

TX_EXTRA_COLS = [
    "in_txs_degree", "out_txs_degree", "total_BTC", "fees", "size",
    "num_input_addresses", "num_output_addresses",
    "in_BTC_min", "in_BTC_max", "in_BTC_mean", "in_BTC_median", "in_BTC_total",
    "out_BTC_min", "out_BTC_max", "out_BTC_mean", "out_BTC_median", "out_BTC_total",
]
TXS_FEATURES_COLS = (
    ["txId", "Time step"]
    + [f"Local_feature_{i}" for i in range(1, 94)]
    + [f"Aggregate_feature_{i}" for i in range(1, 73)]
    + TX_EXTRA_COLS
)

_WALLET_GROUPS = [
    "btc_transacted", "btc_sent", "btc_received", "fees", "fees_as_share",
    "blocks_btwn_txs", "blocks_btwn_input_txs", "blocks_btwn_output_txs",
]
WALLET_FEATURE_COLS = (
    ["address", "Time step", "num_txs_as_sender", "num_txs_as receiver",
     "first_block_appeared_in", "last_block_appeared_in", "lifetime_in_blocks",
     "total_txs", "first_sent_block", "first_received_block",
     "num_timesteps_appeared_in"]
    + [f"{g}_{s}" for g in _WALLET_GROUPS for s in STATS]
    + ["num_addr_transacted_multiple"]
    + [f"transacted_w_address_{s}" for s in STATS]
)
WALLET_COMBINED_COLS = WALLET_FEATURE_COLS[:2] + ["class"] + WALLET_FEATURE_COLS[2:]

# file name -> (kind, expected columns)
EXPECTED_FILES: dict[str, tuple[str, list[str]]] = {
    "AddrAddr_edgelist.csv": ("addr_edges", ["input_address", "output_address"]),
    "AddrTx_edgelist.csv": ("addr_tx", ["input_address", "txId"]),
    "TxAddr_edgelist.csv": ("tx_addr", ["txId", "output_address"]),
    "txs_classes.csv": ("tx_classes", ["txId", "class"]),
    "txs_edgelist.csv": ("tx_edges", ["txId1", "txId2"]),
    "txs_features.csv": ("tx_features", TXS_FEATURES_COLS),
    "wallets_classes.csv": ("wallet_classes", ["address", "class"]),
    "wallets_features.csv": ("wallet_features", WALLET_FEATURE_COLS),
    "wallets_features_classes_combined.csv": ("wallet_combined", WALLET_COMBINED_COLS),
}

ADDRESS_COLS = {"address", "input_address", "output_address"}
TX_ID_COLS = {"txId", "txId1", "txId2"}


def is_anonymised_tx_feature(col: str) -> bool:
    """Anonymised tx features -> float32 is enough. Everything else stays float64
    (BTC amounts, block heights) so evidence values are not rounded."""
    return col.startswith("Local_feature_") or col.startswith("Aggregate_feature_")


def is_nonnegative_expected(file_kind: str, col: str) -> bool:
    """Columns where a negative value would be suspicious (reported, never 'fixed')."""
    if file_kind in ("wallet_features", "wallet_combined"):
        return col not in {"address", "Time step", "class"}
    if file_kind == "tx_features":
        return col in set(TX_EXTRA_COLS)
    return False
