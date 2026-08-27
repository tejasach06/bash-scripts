#!/usr/bin/env python3
"""
Contract test: feed extractor output into InventoryMGR's normalize_csv_row.

Usage: /home/tejas/Projects/InventoryMGR/backend/.venv/bin/python contract_test.py /path/to/inventory.csv

Requires: InventoryMGR backend venv interpreter (uses app.services.csv_import).
"""
import sys
import csv
from pathlib import Path


def run_contract_test(csv_path: str) -> int:
    # Add InventoryMGR backend to path
    inv_mgr = Path(__file__).parent.parent.parent / "InventoryMGR" / "backend"
    sys.path.insert(0, str(inv_mgr))

    try:
        from app.services.csv_import import normalize_csv_row, parse_csv_bytes
    except ImportError as e:
        print(f"[FAIL] InventoryMGR csv_import not importable: {e}", file=sys.stderr)
        return 1

    content = Path(csv_path).read_bytes()
    try:
        rows, ignored = parse_csv_bytes(content)
    except Exception as e:
        print(f"[FAIL] parse_csv_bytes failed: {e}", file=sys.stderr)
        return 1
    if ignored:
        print(f"[FAIL] Ignored columns: {ignored}")
        return 1

    all_errors = []
    for i, row in enumerate(rows):
        normalized, errors = normalize_csv_row(row)
        if errors:
            all_errors.extend([f"Row {i+1}: {e['field']}: {e['message']}" for e in errors])
        if normalized is None:
            all_errors.append(f"Row {i+1}: normalization returned None")

    if all_errors:
        print("[FAIL] Contract violations:")
        for err in all_errors:
            print(f"  {err}")
        return 1

    print(f"[PASS] {len(rows)} row(s) validated against InventoryMGR parser (origin/main)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 contract_test.py <csv_file>")
        sys.exit(2)
    sys.exit(run_contract_test(sys.argv[1]))