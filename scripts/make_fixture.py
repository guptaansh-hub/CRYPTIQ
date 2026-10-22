"""Create a SYNTHETIC mini dataset (not real data) to smoke-test the pipeline:
   python scripts/make_fixture.py data/fixture_raw
   python scripts/run_audit.py --raw data/fixture_raw --out data/fixture_processed"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptiq_data.synthetic import build_fixture
build_fixture(sys.argv[1] if len(sys.argv) > 1 else "data/fixture_raw")
print("Synthetic fixture written. It is NOT real data.")
