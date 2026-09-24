#!/usr/bin/env python3
"""Validates scout extraction JSON against expected schema."""
import json
import sys

REQUIRED_KEYS = {
    "schema_version", "strategy", "timestamp", "file_tree",
    "file_contents", "suspicious_indicators", "extraction_canary",
    "file_count", "total_size_bytes"
}

REQUIRED_SUSPICIOUS = {
    "symlinks_outside_target", "control_char_filenames",
    "hidden_directories", "binary_as_text", "oversized_files",
    "injection_pattern_filenames"
}

def validate(path: str) -> tuple[bool, list[str]]:
    errors = []

    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON: {e}"]
    except FileNotFoundError:
        return False, [f"File not found: {path}"]

    # Check top-level keys
    missing = REQUIRED_KEYS - set(data.keys())
    if missing:
        errors.append(f"Missing top-level keys: {missing}")

    # Check schema version
    if data.get("schema_version") != "1.0":
        errors.append(f"Unknown schema version: {data.get('schema_version')}")

    # Check strategy
    if data.get("strategy") not in ("structured", "random"):
        errors.append(f"Invalid strategy: {data.get('strategy')}")

    # Check file_tree is list
    if not isinstance(data.get("file_tree"), list):
        errors.append("file_tree must be an array")
    else:
        for i, entry in enumerate(data["file_tree"][:5]):  # Spot check first 5
            if not isinstance(entry, dict):
                errors.append(f"file_tree[{i}] is not an object")
            elif not all(k in entry for k in ("path", "type", "size")):
                errors.append(f"file_tree[{i}] missing required fields")

    # Check file_contents is dict
    if not isinstance(data.get("file_contents"), dict):
        errors.append("file_contents must be an object")

    # Check suspicious_indicators
    susp = data.get("suspicious_indicators", {})
    if not isinstance(susp, dict):
        errors.append("suspicious_indicators must be an object")
    else:
        missing_susp = REQUIRED_SUSPICIOUS - set(susp.keys())
        if missing_susp:
            errors.append(f"Missing suspicious indicator keys: {missing_susp}")

    # Check extraction canary
    canary = data.get("extraction_canary", "")
    if not canary:
        errors.append("extraction_canary is empty")

    # Check numeric fields
    for field in ("file_count", "total_size_bytes"):
        val = data.get(field)
        if not isinstance(val, (int, float)):
            errors.append(f"{field} must be numeric, got {type(val).__name__}")

    return len(errors) == 0, errors


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <extraction.json>", file=sys.stderr)
        sys.exit(2)

    valid, errors = validate(sys.argv[1])
    if valid:
        print("VALID")
        sys.exit(0)
    else:
        print("INVALID")
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)
