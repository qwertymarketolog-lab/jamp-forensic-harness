#!/usr/bin/env python3
"""
JAMP S1 Execution Layer.

OUT-OF-TREE ONLY.
Candidate execution is fail-closed: no mocks, fallbacks, or substitute
implementations are permitted.
"""

from __future__ import annotations

import hashlib
import json
import argparse
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CANDIDATE_SHA = "0b0f15d4615cb129382c25af8859d450ac1193ff"
ORACLE_SPEC_HASH = "oracle-v0-spec-hash-sha256:7f83b165"

SEEDS = (
    42069, 104729, 1299709, 15485863, 32452843,
    65537, 131071, 262144, 524287, 1048573,
)

VECTORS = tuple(range(1, 11))

ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
LEDGER_PATH = ARTIFACT_DIR / "s1-r2.ndjson"


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def control_graph() -> dict[str, Any]:
    return {
        "nodes": [
            "source_ref",
            "raw_object",
            "observation_id",
            "atomic_payload",
        ],
        "edges": [
            ["source_ref", "raw_object"],
            ["raw_object", "observation_id"],
            ["observation_id", "atomic_payload"],
        ],
    }


def base_payload(seed: int) -> dict[str, Any]:
    return {
        "raw_observation_ref": f"source-{seed}",
        "raw_observation_hash": sha256({"seed": seed}),
        "atomic_payload": [
            {
                "observation_id": "obs-001",
                "source_ref": "ref-001",
                "real_part": "1.0",
                "imag_part": "2.0",
                "metadata": {"precision_dps": 30},
            },
            {
                "observation_id": "obs-002",
                "source_ref": "ref-002",
                "real_part": "3.0",
                "imag_part": "4.0",
                "metadata": {"precision_dps": 30},
            },
        ],
        "provenance_graph": control_graph(),
        "claims_layer": [],
    }


def mutate(payload: dict[str, Any], vector: int, seed: int) -> dict[str, Any]:
    """Exactly one declared structural mutation."""
    result = json.loads(json.dumps(payload))

    atoms = result["atomic_payload"]
    graph = result["provenance_graph"]

    if vector == 1:
        # Exactly one field mutation; cardinality remains N=2.
        atoms[1]["source_ref"] = atoms[0]["source_ref"]

    elif vector == 2:
        # Exactly one field mutation; cardinality remains N=2.
        atoms[1]["observation_id"] = atoms[0]["observation_id"]

    elif vector == 3:
        # orphan graph node
        graph["nodes"].append(f"orphan-{seed}")

    elif vector == 4:
        # remove mandatory edge
        graph["edges"].pop()

    elif vector == 5:
        # swap observation_id/source_ref roles
        atom = atoms[0]
        atom["observation_id"], atom["source_ref"] = (
            atom["source_ref"],
            atom["observation_id"],
        )

    elif vector == 6:
        # cardinality shift
        atoms.clear()

    elif vector == 7:
        # strict type mutation: str -> int, no cast
        atoms[0]["source_ref"] = seed

    elif vector == 8:
        # raw Unicode identity mutation
        atoms[0]["source_ref"] = atoms[0]["source_ref"] + "\u200b"

    elif vector == 9:
        # incomplete metadata
        atoms[0]["metadata"].pop("precision_dps", None)

    elif vector == 10:
        # payload-level control-looking injection; never trusted as control
        result["atomic_payload"][0]["verdict"] = "PASS"

    else:
        raise ValueError(f"GENERATOR_ERROR: unknown vector {vector}")

    return result


def oracle(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Independent declarative structural reducer.

    This does not execute candidate code.
    """
    atoms = payload.get("atomic_payload")
    graph = payload.get("provenance_graph")

    if not isinstance(atoms, list) or not isinstance(graph, dict):
        return {
            "terminal_status": "INVALID",
            "halt_reasons": [
                {
                    "stage": "EXP31",
                    "diagnostic_code": "META_INCOMPLETE",
                }
            ],
        }

    node_ids = graph.get("nodes", [])
    edges = graph.get("edges", [])

    if len(atoms) == 0:
        return {
            "terminal_status": "TERMINAL_HALT",
            "halt_reasons": [
                {
                    "stage": "N1",
                    "diagnostic_code": "CARDINALITY_VIOLATION",
                }
            ],
        }

    if len({a.get("observation_id") for a in atoms}) != len(atoms):
        return {
            "terminal_status": "TERMINAL_HALT",
            "halt_reasons": [
                {
                    "stage": "N2",
                    "diagnostic_code": "UNIQUENESS_VIOLATION",
                }
            ],
        }

    required_edges = {
        ("source_ref", "raw_object"),
        ("raw_object", "observation_id"),
        ("observation_id", "atomic_payload"),
    }

    actual_edges = {tuple(edge) for edge in edges}

    if not required_edges.issubset(actual_edges):
        return {
            "terminal_status": "INVALID",
            "halt_reasons": [
                {
                    "stage": "EXP31",
                    "diagnostic_code": "BROKEN_LINK",
                }
            ],
        }

    expected_nodes = {
        "source_ref",
        "raw_object",
        "observation_id",
        "atomic_payload",
    }

    if set(node_ids) != expected_nodes:
        return {
            "terminal_status": "INVALID",
            "halt_reasons": [
                {
                    "stage": "EXP31",
                    "diagnostic_code": "ORPHAN_OR_MISSING_NODES",
                }
            ],
        }

    for atom in atoms:
        metadata = atom.get("metadata", {})
        if "precision_dps" not in metadata:
            return {
                "terminal_status": "INCONCLUSIVE",
                "halt_reasons": [
                    {
                        "stage": "EXP31",
                        "diagnostic_code": "META_INCOMPLETE",
                    }
                ],
            }

        if not (
            type(atom.get("source_ref")) is str
            and type(atom.get("observation_id")) is str
        ):
            return {
                "terminal_status": "INVALID",
                "halt_reasons": [
                    {
                        "stage": "EXP31",
                        "diagnostic_code": "STRICT_IDENTITY_FAIL",
                    }
                ],
            }

        if "verdict" in atom:
            return {
                "terminal_status": "TERMINAL_HALT",
                "halt_reasons": [
                    {
                        "stage": "EXP31",
                        "diagnostic_code": "SEMANTIC_OVERREACH",
                    }
                ],
            }

    return {
        "terminal_status": "TERMINAL_PASS",
        "halt_reasons": [],
    }


def candidate_adapter(
    jamp_root: Path,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Inspect only the pinned candidate revision.

    No mock/fallback implementation is allowed.
    """
    try:
        actual = subprocess.check_output(
            ["git", "-C", str(jamp_root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        return {
            "execution_status": "ENV_FAILURE",
            "error": f"candidate git inspection failed: {exc}",
        }

    if actual != CANDIDATE_SHA:
        return {
            "execution_status": "ENV_FAILURE",
            "error": f"candidate SHA mismatch: {actual}",
        }

    with tempfile.TemporaryDirectory(prefix="jamp-s1-candidate-") as tmp:
        archive = Path(tmp) / "candidate.tar"
        extract_root = Path(tmp) / "candidate"
        try:
            with archive.open("wb") as fh:
                subprocess.run(
                    ["git", "-C", str(jamp_root), "archive", "--format=tar",
                     CANDIDATE_SHA],
                    check=True,
                    stdout=fh,
                    stderr=subprocess.PIPE,
                )
            extract_root.mkdir()
            subprocess.run(
                ["tar", "-xf", str(archive), "-C", str(extract_root)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            candidate_path = (
                extract_root / "tests" / "research" / "exp31" / "candidate.py"
            )
            if not candidate_path.is_file():
                return {
                    "execution_status": "ENV_FAILURE",
                    "error": "pinned candidate.py not found in archive",
                }

            import importlib.util

            spec = importlib.util.spec_from_file_location(
                "jamp_exp31_candidate", candidate_path
            )
            if spec is None or spec.loader is None:
                return {
                    "execution_status": "ENV_FAILURE",
                    "error": "unable to load pinned candidate module",
                }
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            result = module.execute(payload)
            if not isinstance(result, dict):
                return {
                    "execution_status": "ENV_FAILURE",
                    "error": "candidate execute(payload) returned non-dict",
                }
            return {
                "execution_status": "OK",
                "result": result,
            }
        except (OSError, subprocess.CalledProcessError, Exception) as exc:
            return {
                "execution_status": "ENV_FAILURE",
                "error": f"candidate execution failed: {exc}",
            }


def differential(
    candidate: dict[str, Any],
    oracle_result: dict[str, Any],
    *,
    seed: int,
    vector: int,
    original: dict[str, Any],
    mutated: dict[str, Any],
    fingerprint: str,
) -> dict[str, Any]:

    execution_status = candidate["execution_status"]

    if execution_status != "OK":
        return {
            "candidate_sha": CANDIDATE_SHA,
            "oracle_spec_hash": ORACLE_SPEC_HASH,
            "seed": seed,
            "vector": vector,
            "mutation_fingerprint": fingerprint,
            "original_payload_fingerprint": sha256(original),
            "mutated_payload_fingerprint": sha256(mutated),
            "candidate_verdict": None,
            "oracle_verdict": oracle_result,
            "ordered_halt_reasons": [],
            "diagnostic_codes": ["ENV_FAILURE"],

            "divergence_classification": None,
            "execution_timestamp": datetime.now(timezone.utc).isoformat(),
            "generator_status": "OK",
            "execution_status": execution_status,
        }

    candidate_result = candidate["result"]
    n3_data = candidate_result.get("n3", {})
    candidate_status = n3_data.get("terminal_status")
    candidate_halts = n3_data.get("halt_reasons", [])

    oracle_status = oracle_result.get("terminal_status")
    oracle_halts = oracle_result.get("halt_reasons", [])

    if candidate_status != oracle_status:
        classification = "MISMATCH_STATUS"
    elif candidate_halts != oracle_halts:
        classification = "MISMATCH_TRACE"
    else:
        classification = "MATCH"

    return {
        "candidate_sha": CANDIDATE_SHA,
        "oracle_spec_hash": ORACLE_SPEC_HASH,
        "seed": seed,
        "vector": vector,
        "mutation_fingerprint": fingerprint,
        "original_payload_fingerprint": sha256(original),
        "mutated_payload_fingerprint": sha256(mutated),
        "candidate_verdict": candidate_result,
        "oracle_verdict": oracle_result,
        "ordered_halt_reasons": candidate_halts,
        "diagnostic_codes": sorted({
            item.get("diagnostic_code")
            for item in candidate_halts + oracle_halts
            if isinstance(item, dict) and item.get("diagnostic_code")
        }),
        "divergence_classification": classification,
        "execution_timestamp": datetime.now(timezone.utc).isoformat(),
        "generator_status": "OK",
        "execution_status": "OK",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jamp-mirror", default=os.environ.get("JAMP_MIRROR_PATH"))
    args = parser.parse_args()

    harness_root = Path(__file__).resolve().parent
    jamp_root = (
        Path(args.jamp_mirror).expanduser().resolve()
        if args.jamp_mirror
        else (harness_root / ".." / "JAMP").resolve()
    )

    if not jamp_root.is_dir():
        raise SystemExit("JAMP repository not found")

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    records = []

    for seed in SEEDS:
        for vector in VECTORS:
            original = base_payload(seed)
            mutated = mutate(original, vector, seed)
            fingerprint = sha256(
                {
                    "seed": seed,
                    "vector": vector,
                    "control_graph": control_graph(),
                    "mutated_payload": mutated,
                }
            )

            candidate = candidate_adapter(jamp_root, mutated)
            oracle_result = oracle(mutated)

            record = differential(
                candidate,
                oracle_result,
                seed=seed,
                vector=vector,
                original=original,
                mutated=mutated,
                fingerprint=fingerprint,
            )
            records.append(record)

    with LEDGER_PATH.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
            ) + "\n")

    failures = sum(
        r["execution_status"] == "ENV_FAILURE"
        for r in records
    )

    print(json.dumps({
        "spec": "S1-EXECUTION-v0",
        "checks": len(records),
        "execution_failures": failures,
        "expected_fail_closed": failures == 100,
        "artifact": str(LEDGER_PATH),
    }, indent=2))

    return 0 if failures == 100 else 1


if __name__ == "__main__":
    raise SystemExit(main())
