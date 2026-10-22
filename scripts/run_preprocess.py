"""Usage:  python scripts/run_preprocess.py --raw data/raw --out data/processed [--steps all] [--format parquet|csv]"""
import argparse, logging, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptiq_data.preprocess import Preprocessor, STEPS

ap = argparse.ArgumentParser(description="Clean Elliptic++ files into a separate processed folder")
ap.add_argument("--raw", default="data/raw")
ap.add_argument("--out", default="data/processed")
ap.add_argument("--steps", default="all", help="comma list of: " + ",".join(STEPS) + " (index must run first)")
ap.add_argument("--format", choices=["parquet", "csv"], default=None, help="default: parquet if pyarrow installed")
ap.add_argument("--chunksize", type=int, default=250_000)
ap.add_argument("--sample-rows", type=int, default=None)
ap.add_argument("--label-map", default="config/label_map.json")
ap.add_argument("--lock-raw", action="store_true", help="mark raw CSVs read-only")
ap.add_argument("--hash-raw", action="store_true", help="record SHA-256 of raw files in the manifest (slow)")
a = ap.parse_args()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
steps = STEPS if a.steps == "all" else a.steps.split(",")
Preprocessor(a.raw, a.out, a.format, a.chunksize, a.sample_rows, a.label_map, a.lock_raw, a.hash_raw).run(steps)
print(f"\nDone. Outputs and _manifest.json are in {a.out}")
