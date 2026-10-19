import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models import Role, EvaluationConfig
from backend.app.auth import create_signed_token, verify_signed_token, quota_mgr
from backend.app.audit import audit_mgr
from backend.app.mock_model import mock_model_service
from backend.app.orchestrator import EvaluationOrchestrator

client = TestClient(app)


def test_cryptographic_bearer_token_issue_and_verify():
    """Enterprise Auth: Test HMAC-SHA256 bearer token issuance and tamper detection."""
    # 1. Issue token via API
    res = client.post("/api/auth/token", json={"user_id": "auditor-alice", "role": "reviewer"})
    assert res.status_code == 200
    data = res.json()
    token = data["access_token"]
    assert token.startswith("ey")  # Base64url JWT header

    # 2. Access protected endpoint with Bearer token
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["user_id"] == "auditor-alice"
    assert me_data["role"] == "reviewer"
    assert me_data["auth_mode"] == "cryptographic_bearer"

    # 3. Tamper token payload and verify rejection
    parts = token.split(".")
    tampered_token = f"{parts[0]}.{parts[1][:-4]}AAAA.{parts[2]}"
    tamper_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert tamper_res.status_code == 401
    assert "signature verification failed" in tamper_res.json()["detail"].lower()


def test_external_checkpoint_anchor_lifecycle():
    """Enterprise Audit: Test external cryptographic checkpoint anchoring and verification."""
    # 1. Create external checkpoint
    ckpt = audit_mgr.create_checkpoint(description="Auditor Quarterly Anchor")
    assert ckpt.checkpoint_id.startswith("ckpt_")
    assert len(ckpt.signature) > 64
    assert len(ckpt.merkle_root) == 64

    # 2. Verify checkpoint against chain
    verif = audit_mgr.verify_checkpoint(ckpt)
    assert verif["is_signature_valid"] is True
    assert verif["is_chain_matched"] is True
    assert verif["is_overall_valid"] is True

    # 3. Test API endpoint for checkpoints
    api_res = client.get("/api/audit/checkpoints", headers={"X-Bayora-Role": "reviewer"})
    assert api_res.status_code == 200
    ckpts = api_res.json()
    assert len(ckpts) > 0


def test_model_output_leakage_redaction():
    """LLM Threat Surface: Test egress sanitization and exfiltration prevention."""
    test_leak = (
        "Output contains FAKE-CANARY-TOKEN-RED-TEAM-DO-NOT-LEAK-7a91bf and internal bayora-sec-orchestrator-token-abc"
    )
    sanitized, was_caught = mock_model_service._scan_and_sanitize_output(test_leak)
    assert was_caught is True
    assert "FAKE-CANARY" not in sanitized
    assert "bayora-sec" not in sanitized
    assert "[REDACTED_CANARY_SECRET]" in sanitized
    assert "[REDACTED_INTERNAL_ORCHESTRATOR_TOKEN]" in sanitized


def test_concurrency_quota_enforcement():
    """Resource Governance: Test per-role concurrency limits."""
    # Acquire slots
    slot1 = quota_mgr.acquire_run_slot(Role.OPERATOR)
    slot2 = quota_mgr.acquire_run_slot(Role.OPERATOR)
    # Third should exceed quota
    slot3 = quota_mgr.acquire_run_slot(Role.OPERATOR)

    assert slot1 is True
    assert slot2 is True
    assert slot3 is False

    # Clean up
    quota_mgr.release_run_slot(Role.OPERATOR)
    quota_mgr.release_run_slot(Role.OPERATOR)


def test_scientific_repeatability_manifest_fields():
    """Scientific Reproducibility: Verify enriched manifest with weights digest, environment & Merkle root."""
    orch = EvaluationOrchestrator()
    cfg = EvaluationConfig(
        name="Enriched Scientific Run",
        model_id="mock-safety-llama-8b-v1",
        test_case_ids=["tc-001"],
    )
    run = orch.create_run(cfg, "evaluator-1")
    assert run.model_weights_digest != ""
    assert "system" in run.runtime_environment
    assert run.rng_seed == 42
    assert run.test_suite_merkle_root != ""

    manifest_dict = orch._generate_manifest_dict(run)
    assert "model_weights_digest" in manifest_dict
    assert "hardware_fingerprint" in manifest_dict
    assert "test_suite_merkle_root" in manifest_dict


def test_key_rotation_and_audit():
    """Secrets Management: Test Ed25519 signing key rotation."""
    res = audit_mgr.rotate_signing_keys(actor="security-officer-bob")
    assert res["status"] == "KEY_ROTATED"
    assert res["retired_fingerprint"] != ""
    assert res["new_fingerprint"] != ""
    assert res["retired_fingerprint"] != res["new_fingerprint"]

    # Verify rotation event is present in audit log
    events = audit_mgr.read_events()
    last_event = events[-1]
    assert last_event.event_type == "ed25519_key_rotated"
    assert last_event.actor == "security-officer-bob"
