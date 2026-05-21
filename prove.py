#!/usr/bin/env python3
import argparse
import hashlib
import json
import sys
from typing import Any

PROOF_VERSION = "v1"
ROOT_RECORD_VERSION = "v1"
PROOF_HASH_DOMAIN_VERSION = "security-audit-known-finding-proof-v1"


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def public_root_record_commitment_id(root: str) -> str:
    return sha256_hex(f"{ROOT_RECORD_VERSION}:public-root:{root}")


def real_leaf_commitment(proof: dict[str, Any]) -> str:
    finding = proof["finding"]
    payload = json.dumps(
        {
            "findingId": finding["findingId"],
            "runId": finding["runId"],
            "safeSummary": finding["safeSummary"],
            "safeSummarySha256": finding["safeSummarySha256"],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return sha256_hex(
        ":".join(
            [
                f"{PROOF_HASH_DOMAIN_VERSION}:real",
                finding["commitmentSalt"],
                payload,
            ]
        )
    )


def combine_proof_hashes(left: str, right: str) -> str:
    return sha256_hex(f"{PROOF_HASH_DOMAIN_VERSION}:parent:{left}:{right}")


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_string(obj: dict[str, Any], key: str, label: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        fail(f"{label}.{key} must be a string")
    return value


def verify(root_record: dict[str, Any], proof: dict[str, Any]) -> str:
    if require_string(root_record, "version", "fingerprint") != ROOT_RECORD_VERSION:
        fail("unsupported fingerprint version")
    if require_string(proof, "version", "proof") != PROOF_VERSION:
        fail("unsupported proof version")
    if require_string(root_record, "hashAlgorithm", "fingerprint") != "sha256":
        fail("unsupported fingerprint hashAlgorithm")
    if require_string(proof, "hashAlgorithm", "proof") != "sha256":
        fail("unsupported proof hashAlgorithm")

    fingerprint_root = require_string(root_record, "root", "fingerprint")
    fingerprint_commitment_id = require_string(root_record, "commitmentId", "fingerprint")
    if public_root_record_commitment_id(fingerprint_root) != fingerprint_commitment_id:
        fail("fingerprint commitmentId does not match its root")

    if not isinstance(proof.get("finding"), dict):
        fail("proof.finding must be an object")
    if not isinstance(proof.get("proof"), list):
        fail("proof.proof must be an array")

    finding = proof["finding"]
    safe_summary = require_string(finding, "safeSummary", "proof.finding")
    safe_summary_sha256 = require_string(finding, "safeSummarySha256", "proof.finding")
    if sha256_hex(safe_summary) != safe_summary_sha256:
        fail("safeSummarySha256 does not match safeSummary")

    commitment = real_leaf_commitment(proof)
    if commitment != require_string(finding, "commitment", "proof.finding"):
        fail("finding commitment does not match disclosed summary")

    computed_root = commitment
    for index, step in enumerate(proof["proof"]):
        if not isinstance(step, dict):
            fail(f"proof.proof[{index}] must be an object")
        if step.get("level") != index:
            fail(f"proof.proof[{index}].level must equal {index}")
        sibling_hash = require_string(step, "siblingHash", f"proof.proof[{index}]")
        side = step.get("side")
        if side == "left":
            computed_root = combine_proof_hashes(sibling_hash, computed_root)
        elif side == "right":
            computed_root = combine_proof_hashes(computed_root, sibling_hash)
        else:
            fail(f"proof.proof[{index}].side must be left or right")

    proof_root = require_string(proof, "root", "proof")
    if computed_root != proof_root:
        fail("proof path does not produce proof.root")
    if computed_root != fingerprint_root:
        fail("proof.root does not match fingerprint.root")

    return computed_root


def load_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify an Exa known-finding proof packet.")
    parser.add_argument("fingerprint_json", help="Path to fingerprint.json / public root record JSON")
    parser.add_argument("proof_json", help="Path to known-finding proof packet JSON")
    args = parser.parse_args()

    root = verify(load_json(args.fingerprint_json), load_json(args.proof_json))
    print(f"OK: proof matches fingerprint root {root}")


if __name__ == "__main__":
    main()