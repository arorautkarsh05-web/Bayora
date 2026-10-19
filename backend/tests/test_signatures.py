import pytest
from backend.app.audit import audit_mgr


def test_ed25519_manifest_signing_and_verification():
    """PR-8 Acceptance Test: Manifest can be signed and independently verified with Ed25519."""
    manifest = {
        "manifest_version": "1.0",
        "run_id": "run_demo_100",
        "run_name": "Demo Evaluation Run",
        "model_id": "mock-safety-llama-8b-v1",
        "policy_id": "policy-standard-shield",
        "total_tests": 4,
        "outcome_summary": {"blocked_by_defense": 3, "benign_success": 1},
        "test_fingerprints": ["hash_1", "hash_2", "hash_3", "hash_4"],
        "started_at": "2026-10-04T12:00:00Z",
        "completed_at": "2026-10-04T12:00:02Z",
    }

    signature = audit_mgr.sign_manifest(manifest)
    assert signature is not None
    assert len(signature) > 64  # Hex encoded Ed25519 signature

    # Verify signature
    assert audit_mgr.verify_manifest_signature(manifest, signature) is True

    # Tampered manifest should fail verification
    tampered_manifest = dict(manifest)
    tampered_manifest["total_tests"] = 999  # Tampered field
    assert audit_mgr.verify_manifest_signature(tampered_manifest, signature) is False
