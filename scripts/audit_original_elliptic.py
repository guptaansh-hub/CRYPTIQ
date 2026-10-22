
import json
from pathlib import Path

import numpy as np
import pandas as pd

RAW = Path("data/raw")
OUT = Path("data/processed/original_elliptic")
OUT.mkdir(parents=True, exist_ok=True)

FEATURES = RAW / "elliptic_txs_features.csv"
CLASSES = RAW / "elliptic_txs_classes.csv"
EDGES = RAW / "elliptic_txs_edgelist.csv"

report = {"dataset": "Original Elliptic", "checks": {}}

# 1. Read features without a header.
features = pd.read_csv(FEATURES, header=None)
feature_ids = features.iloc[:, 0]

report["checks"]["features"] = {
    "rows": len(features),
    "columns": features.shape[1],
    "null_transaction_ids": int(feature_ids.isna().sum()),
    "duplicate_transaction_ids": int(feature_ids.duplicated().sum()),
    "null_feature_cells": int(features.iloc[:, 1:].isna().sum().sum()),
    "nonfinite_feature_cells": int(
        np.isinf(features.iloc[:, 1:].to_numpy(dtype=float)).sum()
    ),
}

# The first two columns are transaction ID and time step.
time_steps = pd.to_numeric(features.iloc[:, 1], errors="coerce")
report["checks"]["time_steps"] = {
    "null_time_steps": int(time_steps.isna().sum()),
    "distinct_time_steps": int(time_steps.nunique()),
    "minimum": None if time_steps.dropna().empty else int(time_steps.min()),
    "maximum": None if time_steps.dropna().empty else int(time_steps.max()),
}

# 2. Read class labels without interpreting numeric codes.
classes = pd.read_csv(CLASSES)
class_ids = classes["txId"]

report["checks"]["classes"] = {
    "rows": len(classes),
    "unique_transaction_ids": int(class_ids.nunique()),
    "null_transaction_ids": int(class_ids.isna().sum()),
    "duplicate_transaction_ids": int(class_ids.duplicated().sum()),
    "class_counts": {
        str(k): int(v)
        for k, v in classes["class"].value_counts(dropna=False).items()
    },
    "numeric_class_mapping_confirmed": False,
}

feature_id_set = set(feature_ids.dropna())
class_id_set = set(class_ids.dropna())

report["checks"]["feature_class_id_coverage"] = {
    "feature_ids_missing_from_classes": len(feature_id_set - class_id_set),
    "class_ids_missing_from_features": len(class_id_set - feature_id_set),
}

# 3. Check graph edges.
edges = pd.read_csv(EDGES)
source = edges["txId1"]
target = edges["txId2"]

report["checks"]["edges"] = {
    "rows": len(edges),
    "duplicate_edges": int(edges.duplicated().sum()),
    "self_loops": int((source == target).sum()),
    "null_source_ids": int(source.isna().sum()),
    "null_target_ids": int(target.isna().sum()),
    "source_ids_missing_from_features": len(set(source.dropna()) - feature_id_set),
    "target_ids_missing_from_features": len(set(target.dropna()) - feature_id_set),
}

# 4. Save a separate report; never write to the raw directory.
json_path = OUT / "audit_report.json"
md_path = OUT / "audit_report.md"

json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

lines = [
    "# Original Elliptic Dataset Audit",
    "",
    "> This is a structural audit, not proof of fraud or exchange attribution.",
    "> Numeric class meanings have not been confirmed by this script.",
    "",
]

for section, details in report["checks"].items():
    lines.extend([f"## {section.replace('_', ' ').title()}", ""])
    for key, value in details.items():
        lines.append(f"- **{key.replace('_', ' ')}:** {value}")
    lines.append("")

md_path.write_text("\n".join(lines), encoding="utf-8")

print("Audit completed.")
print("Markdown report:", md_path)
print("JSON report:", json_path)
