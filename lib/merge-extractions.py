#!/usr/bin/env python3
"""
Merge two scout extractions after consistency check.
Exits non-zero if extractions disagree on structural properties.
Outputs merged JSON to stdout.
"""
import json
import sys


def load(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def consistency_check(a: dict, b: dict) -> tuple[bool, list[str]]:
    """Compare two extractions for structural agreement."""
    issues = []

    # 1. File trees should agree on structure
    a_paths = {e["path"] for e in a.get("file_tree", [])}
    b_paths = {e["path"] for e in b.get("file_tree", [])}

    # Trees should have significant overlap (at least 80% Jaccard)
    if a_paths and b_paths:
        intersection = a_paths & b_paths
        union = a_paths | b_paths
        jaccard = len(intersection) / len(union) if union else 0
        if jaccard < 0.8:
            issues.append(
                f"File tree Jaccard similarity too low: {jaccard:.2f} "
                f"(A: {len(a_paths)} files, B: {len(b_paths)} files, "
                f"shared: {len(intersection)})"
            )

    # 2. File counts should be close
    a_count = a.get("file_count", 0)
    b_count = b.get("file_count", 0)
    if a_count > 0 and b_count > 0:
        ratio = min(a_count, b_count) / max(a_count, b_count)
        if ratio < 0.9:
            issues.append(
                f"File count mismatch: A={a_count}, B={b_count} (ratio={ratio:.2f})"
            )

    # 3. Total size should be close
    a_size = a.get("total_size_bytes", 0)
    b_size = b.get("total_size_bytes", 0)
    if a_size > 0 and b_size > 0:
        ratio = min(a_size, b_size) / max(a_size, b_size)
        if ratio < 0.9:
            issues.append(
                f"Total size mismatch: A={a_size}, B={b_size} (ratio={ratio:.2f})"
            )

    # 4. Extraction canary must match in both
    a_canary = a.get("extraction_canary", "MISSING")
    b_canary = b.get("extraction_canary", "MISSING")
    if a_canary != b_canary:
        issues.append(
            f"Extraction canary mismatch: A={a_canary!r}, B={b_canary!r}"
        )
    if "MISSING" in (a_canary, b_canary):
        issues.append("Extraction canary MISSING in at least one extraction")

    # 5. Suspicious indicators should not contradict
    a_susp = a.get("suspicious_indicators", {})
    b_susp = b.get("suspicious_indicators", {})
    for key in ("symlinks_outside_target", "control_char_filenames",
                "hidden_directories", "oversized_files"):
        a_has = len(a_susp.get(key, [])) > 0
        b_has = len(b_susp.get(key, [])) > 0
        if a_has != b_has:
            issues.append(
                f"Suspicious indicator disagreement on '{key}': "
                f"A={'found' if a_has else 'none'}, B={'found' if b_has else 'none'}"
            )

    return len(issues) == 0, issues


def merge(a: dict, b: dict) -> dict:
    """Merge two consistent extractions into combined input for LLM."""
    merged = {
        "schema_version": "1.0",
        "strategy": "merged",
        "timestamp_a": a.get("timestamp", ""),
        "timestamp_b": b.get("timestamp", ""),
        "file_tree": a.get("file_tree", []),  # Use A's tree (structured)
        "file_contents": {},
        "suspicious_indicators": {},
        "extraction_canary": a.get("extraction_canary", ""),
        "file_count": a.get("file_count", 0),
        "total_size_bytes": a.get("total_size_bytes", 0),
    }

    # Merge file contents — union of both, prefer A for duplicates but note overlap
    a_contents = a.get("file_contents", {})
    b_contents = b.get("file_contents", {})

    for path, data in a_contents.items():
        merged["file_contents"][path] = data
        merged["file_contents"][path]["source"] = "extraction-a"

    for path, data in b_contents.items():
        if path in merged["file_contents"]:
            # Both extractions read this file — include B's as alternate view
            merged["file_contents"][f"{path} [alt-view]"] = data
            merged["file_contents"][f"{path} [alt-view]"]["source"] = "extraction-b"
        else:
            merged["file_contents"][path] = data
            merged["file_contents"][path]["source"] = "extraction-b"

    # Merge suspicious indicators — union
    a_susp = a.get("suspicious_indicators", {})
    b_susp = b.get("suspicious_indicators", {})
    for key in set(list(a_susp.keys()) + list(b_susp.keys())):
        a_list = a_susp.get(key, [])
        b_list = b_susp.get(key, [])
        merged["suspicious_indicators"][key] = list(set(a_list + b_list))

    return merged


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <extraction-a.json> <extraction-b.json>",
              file=sys.stderr)
        sys.exit(2)

    a = load(sys.argv[1])
    b = load(sys.argv[2])

    consistent, issues = consistency_check(a, b)

    if not consistent:
        print("CONSISTENCY CHECK FAILED", file=sys.stderr)
        for issue in issues:
            print(f"  - {issue}", file=sys.stderr)
        sys.exit(1)

    result = merge(a, b)
    json.dump(result, sys.stdout, indent=2)
    print(f"\nMerged: {len(result['file_contents'])} files from both extractions",
          file=sys.stderr)
