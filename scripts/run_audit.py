"""Usage:  python scripts/run_audit.py --raw data/raw --out data/processed [--sample-rows 50000]"""
import argparse, logging, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptiq_data.audit import run_audit

ap = argparse.ArgumentParser(description="Read-only audit of the Elliptic++ CSV files")
ap.add_argument("--raw", default="data/raw")
ap.add_argument("--out", default="data/processed")
ap.add_argument("--chunksize", type=int, default=250_000, help="lower this if you run out of RAM")
ap.add_argument("--sample-rows", type=int, default=None, help="quick look: read only first N rows per file (report marked SAMPLED)")
a = ap.parse_args()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
r = run_audit(a.raw, a.out, a.chunksize, a.sample_rows)
print(f"\nDone. Open {Path(a.out) / 'audit' / 'audit_report.md'}")
