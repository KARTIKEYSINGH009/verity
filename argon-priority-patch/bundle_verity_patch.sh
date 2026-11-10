#!/usr/bin/env bash
set -euo pipefail

python3 - << 'EOF'
import zipfile, pathlib

files_to_zip = [
    "policy.py",
    "classifier_features.py",
    "gateway.py",
    "store.py",
    "README.md",
    "bundle_verity_patch.sh",
    "tests/priority_twins.jsonl",
    "tests/test_priorities.py",
]

with zipfile.ZipFile("verity_priority_patch.zip", "w", zipfile.ZIP_DEFLATED) as zf:
    for f in files_to_zip:
        p = pathlib.Path(f)
        if p.exists():
            zf.write(p, arcname=f)
print("Created verity_priority_patch.zip")
EOF
