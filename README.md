# CRYPTIQ - data audit and preprocessing (Stage 1)

Covers the **Elliptic++ CSV files** described in `CRYPTIQ_schema_report.txt`.
GraphSense TagPacks, the FIU-IND registry and live blockchain APIs are **not integrated yet** - no files for
them have been provided. Nothing here claims otherwise.

## Rules the code follows
* `data/raw/` is read-only. Outputs go to `data/processed/` (the code refuses an output folder inside raw,
  verifies raw files are unchanged afterwards, and `--lock-raw` can mark them read-only).
* No scaling/imputation here (that belongs inside the training pipeline, fitted on the train split only).
* Nothing is silently dropped: duplicates, null keys and conflicting labels go to `processed/quarantine/`.
* Class codes are not translated to words until you set `"confirmed": true` in `config/label_map.json`.

## Windows setup (PowerShell)
1. Install Python 3.11 or 3.12 from python.org (tick "Add python.exe to PATH").
2. In the project folder:
   ```
   py -3.12 -m venv .venv
   .venv\Scripts\Activate.ps1      # if blocked: Set-ExecutionPolicy -Scope Process RemoteSigned
   pip install -r requirements.txt
   ```
3. Copy the 9 Elliptic++ CSVs into `data\raw\` (keep the original names). Keep ~3 GB free for outputs.
4. Smoke test on synthetic data (NOT real data):
   ```
   python scripts\make_fixture.py data\fixture_raw
   python scripts\run_audit.py --raw data\fixture_raw --out data\fixture_processed
   ```
5. Audit the real files (read-only, takes several minutes; add `--sample-rows 50000` for a quick look):
   ```
   python scripts\run_audit.py --raw data\raw --out data\processed
   ```
   Read `data\processed\audit\audit_report.md`. Send me that file (or the CRITICAL/WARN rows) before we train anything.
6. Check class values in the audit, confirm them in `config\label_map.json`, then:
   ```
   python scripts\run_preprocess.py --raw data\raw --out data\processed
   ```
   Out of memory? add `--chunksize 100000`. No pyarrow? add `--format csv`.
7. Tests: `python -m pytest -q tests`

## Outputs (`data/processed/`)
`address_index`, `tx_features`, `tx_edges`, `wallet_features`, `addr_edges`, `addr_tx_in`, `tx_addr_out`,
`quarantine/*`, `_manifest.json` (row counts, dropped counts, column renames, label-map status).
Parquet by default, `.csv` with `--format csv`.
