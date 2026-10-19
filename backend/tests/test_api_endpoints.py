from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_api_canaries_and_trips():
    """Requirement 2: API endpoints for canary tokens, trips, and simulation."""
    # List canaries
    res = client.get("/api/canaries", headers={"X-Bayora-Role": "operator", "X-Bayora-User": "admin"})
    assert res.status_code == 200
    canaries = res.json()
    assert len(canaries) >= 3
    # Check that secrets are NOT present
    for c in canaries:
        assert "token_hash" in c
        assert "fake_secret" not in c
        assert "FAKE-CANARY-TOKEN" not in str(c)

    # Simulate trip
    sim_res = client.post(
        "/api/canaries/simulate-trip",
        headers={"X-Bayora-Role": "operator", "X-Bayora-User": "admin"},
        json={"token_id": "canary-red-payload-01", "simulated_role": "blue_team"},
    )
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["status"] == "CANARY_TRIP_RECORDED_AND_BLOCKED"

    # List trips
    trips_res = client.get("/api/canaries/trips", headers={"X-Bayora-Role": "operator", "X-Bayora-User": "admin"})
    assert trips_res.status_code == 200
    trips = trips_res.json()
    assert len(trips) > 0


def test_api_proof_mode_matrix():
    """Requirement 3 & 7: Proof mode endpoint provides tested vs assumed control matrix."""
    res = client.get("/api/security-tests/proof-mode", headers={"X-Bayora-Role": "operator", "X-Bayora-User": "admin"})
    assert res.status_code == 200
    matrix = res.json()
    assert matrix["total_controls"] >= 10
    assert matrix["tested_controls_count"] >= 7
    assert matrix["assumed_controls_count"] >= 4
    assert matrix["passing_tests_count"] >= 7

    # Verify presence of tested mechanisms and documented assumptions
    categories = [c["category"] for c in matrix["controls"]]
    assert "Tested Mechanism" in categories
    assert "Documented Assumption / Limitation" in categories


def test_api_repeatable_run_rerun_and_compare_and_report():
    """Requirement 5 & 6: Rerun, compare runs, and export evidence report."""
    # 1. Create a baseline run
    run_res = client.post(
        "/api/eval/runs",
        headers={"X-Bayora-Role": "operator", "X-Bayora-User": "admin"},
        json={
            "name": "API Baseline Run",
            "model_id": "mock-safety-llama-8b-v1",
            "policy_id": "policy-standard-shield",
            "test_case_ids": ["tc-001", "tc-002"],
            "timeout_seconds": 5.0,
            "simulated_delay": 0.01,
        },
    )
    assert run_res.status_code == 200
    baseline = run_res.json()
    baseline_id = baseline["id"]
    assert baseline["config_fingerprint"] != ""

    # 2. Rerun the baseline
    rerun_res = client.post(
        f"/api/eval/runs/{baseline_id}/rerun",
        headers={"X-Bayora-Role": "operator", "X-Bayora-User": "admin"},
    )
    assert rerun_res.status_code == 200
    rerun = rerun_res.json()
    rerun_id = rerun["id"]
    assert rerun["rerun_of_id"] == baseline_id
    assert rerun["config_fingerprint"] == baseline["config_fingerprint"]

    # 3. Compare the two runs
    compare_res = client.post(
        "/api/eval/runs/compare",
        headers={"X-Bayora-Role": "operator", "X-Bayora-User": "admin"},
        json={"baseline_run_id": baseline_id, "rerun_run_id": rerun_id},
    )
    assert compare_res.status_code == 200
    comp = compare_res.json()
    assert comp["config_fingerprint_match"] is True
    assert comp["reproducibility_percentage"] == 100.0
    assert len(comp["items"]) == 2

    # 4. Evidence Report (JSON)
    rep_res = client.get(
        f"/api/eval/runs/{baseline_id}/evidence-report?format=json",
        headers={"X-Bayora-Role": "operator", "X-Bayora-User": "admin"},
    )
    assert rep_res.status_code == 200
    report = rep_res.json()
    assert report["run_id"] == baseline_id
    assert report["audit_chain_valid"] is True
    assert report["manifest_signature_valid"] is True
    assert len(report["documented_limitations"]) >= 4

    # 5. Evidence Report (Markdown)
    rep_md_res = client.get(
        f"/api/eval/runs/{baseline_id}/evidence-report?format=markdown",
        headers={"X-Bayora-Role": "operator", "X-Bayora-User": "admin"},
    )
    md_content = rep_md_res.text
    assert "# Bayora Security & Evaluation Evidence Report" in md_content
    assert baseline["config_fingerprint"] in md_content


def test_api_token_auth_and_checkpoints():
    """Verify newly added enterprise endpoints for token issuance and checkpointing."""
    # 1. Issue bearer token
    tok_res = client.post("/api/auth/token", json={"user_id": "operator-bob", "role": "operator"})
    assert tok_res.status_code == 200
    token = tok_res.json()["access_token"]

    # 2. Authenticate with Bearer token
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["auth_mode"] == "cryptographic_bearer"

    # 3. Create external checkpoint via API
    ckpt_res = client.post(
        "/api/audit/checkpoints",
        headers={"Authorization": f"Bearer {token}"},
        json={"description": "API Test Checkpoint"},
    )
    assert ckpt_res.status_code == 200
    ckpt_data = ckpt_res.json()
    assert "checkpoint_id" in ckpt_data

    # 4. Verify checkpoint via API
    verif_res = client.post(
        f"/api/audit/checkpoints/{ckpt_data['checkpoint_id']}/verify",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert verif_res.status_code == 200
    assert verif_res.json()["is_overall_valid"] is True

