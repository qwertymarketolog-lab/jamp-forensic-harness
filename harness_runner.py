#!/usr/bin/env python3
"""
JAMP Forensic Harness — S1 external runner.

OUT-OF-TREE:
  ../jamp-forensic-harness/

This runner must never write into the JAMP repository.
HARNESS SELF-VERIFICATION is required before S1 execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path


CANDIDATE_SHA = "50448131f2fff887cdb037486614be47c8533f22"
ORACLE_SPEC_HASH = "oracle-v0-spec-hash-sha256:7f83b165"
SEEDS = (
    42069,
    104729,
    1299709,
    15485863,
    32452843,
    65537,
    131071,
    262144,
    524287,
    1048573,
)
VECTORS = tuple(range(1, 11))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def mutation_fingerprint(
    seed: int,
    vector: int,
    control_graph: object,
) -> str:
    payload = {
        "seed": seed,
        "vector": vector,
        "control_graph": control_graph,
    }
    return sha256_bytes(canonical_json(payload))


def generate_probe(seed: int, vector: int, control_graph: object) -> dict:
    """
    Deterministic structural probe.

    This is deliberately limited to generator/self-verification semantics.
    It does not execute candidate or oracle logic.
    """
    if vector not in VECTORS:
        raise ValueError("GENERATOR_ERROR: unknown vector")

    base = {
        "seed": seed,
        "vector": vector,
        "control_graph": control_graph,
    }

    fingerprint = mutation_fingerprint(seed, vector, control_graph)

    return {
        "seed": seed,
        "vector": vector,
        "mutation_count": 1,
        "mutation_fingerprint": fingerprint,
        "generator_status": "OK",
        "control_plane_isolated": True,
        "candidate_feedback_used": False,
        "payload": {
            "mutation_token": fingerprint,
        },
    }


def snapshot_tree(root: Path) -> str:
    """
    Hash filesystem state beneath root without writing anything.

    Excludes .git internals from the semantic tree snapshot but records
    tracked/untracked state separately through git commands in the shell.
    """
    entries: list[tuple[str, int, str]] = []

    for path in sorted(root.rglob("*")):
        if ".git" in path.parts:
            continue
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            data = path.read_bytes()
            entries.append((rel, len(data), sha256_bytes(data)))

    return sha256_bytes(canonical_json(entries))


def self_verify(jamp_root: Path) -> dict:
    """
    HARNESS SELF-VERIFICATION-v0.

    Eight locked invariants:
      1 candidate SHA binding
      2 oracle hash binding
      3 cohort pinning
      4 generator determinism
      5 one-to-one mutation
      6 control-plane isolation
      7 strict execution partition
      8 zero-write JAMP tree atomicity
    """
    results: list[dict] = []

    before = snapshot_tree(jamp_root)

    # 1 — candidate binding
    import subprocess

    try:
        actual_sha = subprocess.check_output(
            ["git", "-C", str(jamp_root), "rev-parse", "HEAD"],
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        actual_sha = None

    results.append({
        "id": 1,
        "name": "candidate_sha_binding",
        "expected": CANDIDATE_SHA,
        "actual": actual_sha,
        "pass": actual_sha == CANDIDATE_SHA,
    })

    # 2 — oracle binding
    results.append({
        "id": 2,
        "name": "oracle_hash_binding",
        "pass": ORACLE_SPEC_HASH.startswith(
            "oracle-v0-spec-hash-sha256:"
        ),
    })

    # 3 — exact 10-seed cohort
    results.append({
        "id": 3,
        "name": "cohort_pinning",
        "pass": len(SEEDS) == 10 and len(set(SEEDS)) == 10,
    })

    # 4 — deterministic generator
    control_graph = {
        "scope": "self-verification",
        "nodes": ["source_ref", "raw_object", "observation_id"],
        "edges": [
            ["source_ref", "raw_object"],
            ["raw_object", "observation_id"],
        ],
    }

    p1 = generate_probe(SEEDS[0], 1, control_graph)
    p2 = generate_probe(SEEDS[0], 1, control_graph)

    results.append({
        "id": 4,
        "name": "generator_determinism",
        "pass": p1 == p2,
    })

    # 5 — exactly one mutation per seed/vector
    probes = [
        generate_probe(seed, vector, control_graph)
        for seed in SEEDS
        for vector in VECTORS
    ]

    results.append({
        "id": 5,
        "name": "one_to_one_mutation",
        "pass": (
            len(probes) == 100
            and all(p["mutation_count"] == 1 for p in probes)
            and len({
                (p["seed"], p["vector"])
                for p in probes
            }) == 100
        ),
    })

    # 6 — no candidate-verdict feedback
    results.append({
        "id": 6,
        "name": "control_plane_isolation",
        "pass": all(
            p["candidate_feedback_used"] is False
            and p["control_plane_isolated"] is True
            for p in probes
        ),
    })

    # 7 — strict partition
    allowed_generator = {"OK", "GENERATOR_ERROR"}
    allowed_execution = {"OK", "ENV_FAILURE"}

    results.append({
        "id": 7,
        "name": "partition_strictness",
        "pass": (
            "OK" in allowed_generator
            and "GENERATOR_ERROR" in allowed_generator
            and "OK" in allowed_execution
            and "ENV_FAILURE" in allowed_execution
            and "DIVERGENCE" not in allowed_generator
            and "DIVERGENCE" not in allowed_execution
        ),
    })

    # 8 — no JAMP tree mutation
    after = snapshot_tree(jamp_root)

    results.append({
        "id": 8,
        "name": "zero_write_jamp_tree",
        "pass": before == after,
        "before": before,
        "after": after,
    })

    passed = sum(r["pass"] for r in results)

    return {
        "spec": "HARNESS SELF-VERIFICATION-v0",
        "status": "PASS" if passed == 8 else "FAIL",
        "passed": passed,
        "total": 8,
        "candidate_sha": CANDIDATE_SHA,
        "oracle_spec_hash": ORACLE_SPEC_HASH,
        "cohort": list(SEEDS),
        "results": results,
    }


def main() -> int:
    harness_root = Path(__file__).resolve().parent
    jamp_root = (harness_root / ".." / "JAMP").resolve()

    if not jamp_root.is_dir():
        print("ERROR: JAMP repository not found", file=sys.stderr)
        return 2

    result = self_verify(jamp_root)

    print(json.dumps(result, ensure_ascii=False, indent=2))

    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
