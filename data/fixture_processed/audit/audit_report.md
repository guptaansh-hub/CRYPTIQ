# CRYPTIQ data audit

Created: 2026-10-17T03:23:18.695564+00:00  |  sampled rows: None

## Findings

| Level | Code | File | Message |
|---|---|---|---|
| CRITICAL | LEAKAGE_WHOLE_HISTORY | wallets_features.csv | 3/8 rows report num_timesteps_appeared_in larger than the number of time steps seen up to that row -> these columns look like whole-history summaries, i.e. they contain FUTURE information relative to the row's Time step. Temporal evaluation on them will be optimistic. |
| WARN | DUPLICATE_KEYS | txs_features.csv | 2 rows repeat an earlier key ['txId'] (1 are exact full-row duplicates; the rest conflict) |
| WARN | NULLS | txs_features.csv | 1 columns have missing values, e.g. {'Local_feature_5': 2} |
| WARN | NONFINITE | txs_features.csv | infinite values in {'fees': 1} |
| WARN | NEGATIVE_VALUES | txs_features.csv | negatives in ['in_txs_degree', 'out_txs_degree', 'total_BTC', 'fees', 'size'] |
| WARN | DUPLICATE_KEYS | txs_classes.csv | 1 rows repeat an earlier key ['txId'] (0 are exact full-row duplicates; the rest conflict) |
| WARN | DUPLICATE_KEYS | txs_edgelist.csv | 1 rows repeat an earlier key ['txId1', 'txId2'] (1 are exact full-row duplicates; the rest conflict) |
| WARN | DUPLICATE_KEYS | wallets_classes.csv | 1 rows repeat an earlier key ['address'] (0 are exact full-row duplicates; the rest conflict) |
| WARN | DUPLICATE_KEYS | wallets_features.csv | 1 rows repeat an earlier key ['address', 'Time step'] (0 are exact full-row duplicates; the rest conflict) |
| WARN | NULLS | wallets_features.csv | 1 columns have missing values, e.g. {'fees_total': 1} |
| WARN | DUPLICATE_KEYS | wallets_features_classes_combined.csv | 1 rows repeat an earlier key ['address', 'Time step'] (0 are exact full-row duplicates; the rest conflict) |
| WARN | NULLS | wallets_features_classes_combined.csv | 1 columns have missing values, e.g. {'fees_total': 1} |
| WARN | DUPLICATE_KEYS | AddrAddr_edgelist.csv | 1 rows repeat an earlier key ['input_address', 'output_address'] (1 are exact full-row duplicates; the rest conflict) |
| WARN | ADDRESS_FORMAT | AddrAddr_edgelist.csv | addresses not matching a known Bitcoin format (format check only, no checksum): {'output_address': 1, 'input_address': 0} |
| WARN | ADDRESS_WHITESPACE | AddrTx_edgelist.csv | {'input_address': 1} |
| WARN | DUPLICATE_KEYS | TxAddr_edgelist.csv | 1 rows repeat an earlier key ['txId', 'output_address'] (1 are exact full-row duplicates; the rest conflict) |
| WARN | NULLS | TxAddr_edgelist.csv | 1 columns have missing values, e.g. {'output_address': 1} |
| WARN | ADDRESS_FORMAT | TxAddr_edgelist.csv | addresses not matching a known Bitcoin format (format check only, no checksum): {'output_address': 1} |
| WARN | ID_COVERAGE | classes | only 90.91% of classes txIds exist in txs_features |
| WARN | ID_COVERAGE | tx_edges_2 | only 75.00% of tx_edges_2 txIds exist in txs_features |
| WARN | ID_COVERAGE | addr_tx | only 80.00% of addr_tx txIds exist in txs_features |
| WARN | LABEL_CONFLICT | txs_classes.csv | 1 keys carry more than one class |
| WARN | LABEL_CONFLICT | wallets_classes.csv | 1 keys carry more than one class |
| WARN | COMBINED_MISMATCH | wallets_features_classes_combined.csv | 1 rows disagree with wallets_classes.csv |
| WARN | CROSS_TIMESTEP_EDGES | txs_edgelist.csv | 1 edges connect different time steps |
| WARN | LEAKAGE_ADDRESS_REPEATS | wallets_features.csv | 2 addresses occur in several time steps; a random row split would put the same (labelled) address in train and test. Split by time step and group by address. |
| INFO | SELF_LOOPS | txs_edgelist.csv | 1 rows have identical source and target (often change outputs) |
| INFO | SELF_LOOPS | AddrAddr_edgelist.csv | 1 rows have identical source and target (often change outputs) |
| INFO | ID_COVERAGE | wallet_classes | 83.33% of wallet_classes addresses appear in wallet_features |
| INFO | ID_COVERAGE | addr_addr_in | 75.00% of addr_addr_in addresses appear in wallet_features |
| INFO | ID_COVERAGE | addr_addr_out | 80.00% of addr_addr_out addresses appear in wallet_features |
| INFO | TXID_IS_DATASET_ID | txs_* | txId is the dataset's own integer id; the files contain no Bitcoin transaction hash column, so these transactions cannot be looked up on a live explorer from this data alone |
| INFO | CLASS_VALUES | txs_classes.csv | raw class counts {'1': 5, '2': 3, '3': 4} (meaning NOT assumed; see config/label_map.json) |
| INFO | CLASS_VALUES | wallets_classes.csv | raw class counts {'1': 2, '2': 3, '3': 2} (meaning NOT assumed; see config/label_map.json) |

## Per-file summary

| File | Rows | Dup keys | Dup full rows | Cols with nulls |
|---|---|---|---|---|
| txs_features.csv | 14 | 2 | 1 | 1 |
| txs_classes.csv | 12 | 1 | 0 | 0 |
| txs_edgelist.csv | 6 | 1 | 1 | 0 |
| wallets_classes.csv | 7 | 1 | 0 | 0 |
| wallets_features.csv | 8 | 1 | 0 | 1 |
| wallets_features_classes_combined.csv | 8 | 1 | 0 | 1 |
| AddrAddr_edgelist.csv | 6 | 1 | 1 | 0 |
| AddrTx_edgelist.csv | 5 | 0 | 0 | 0 |
| TxAddr_edgelist.csv | 6 | 1 | 1 | 1 |

## Details (JSON)

See `audit_report.json` for ID coverage, label counts, graph/time and leakage numbers.
