import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.models import OutcomeCategory

client = TestClient(app)


def test_create_and_execute_evaluation_run():
    """PR-4, PR-6, PR-9: Complete end-to-end evaluation execution and result verification."""
    payload = {
        "name": "Standard Defensive Evaluation Run",
        "model_id": "mock-safety-llama-8b-v1",
        "policy_id": "policy-standard-shield",
        "test_case_ids": ["tc-001", "tc-002", "tc-004"],
        "timeout_seconds": 5.0,
        "simulated_delay": 0.01,
        "trigger_timeout_test": False,
    }

    response = client.post(
        "/api/eval/runs",
        headers={"X-Bayora-Role": "operator", "X-Bayora-User": "eval_operator"},
        json=payload,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["total_tests"] == 3
    assert len(data["results"]) == 3
    assert data["manifest_signature"] is not None

    # Check results privacy: raw prompts are hashed
    for res in data["results"]:
        assert len(res["prompt_hash"]) == 64  # SHA-256


def test_evaluation_run_timeout_limit_enforcement():
    """PR-7: Workload exceeding timeout is terminated and recorded."""
    payload = {
        "name": "Timeout Limit Verification Run",
        "model_id": "mock-safety-llama-8b-v1",
        "policy_id": "policy-standard-shield",
        "test_case_ids": ["tc-001"],
        "timeout_seconds": 0.2,
        "simulated_delay": 0.01,
        "trigger_timeout_test": True,  # Triggers timeout > 0.2s
    }

    response = client.post(
        "/api/eval/runs",
        headers={"X-Bayora-Role": "operator", "X-Bayora-User": "eval_operator"},
        json=payload,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["timeout_tests"] == 1
    assert data["results"][0]["outcome"] == OutcomeCategory.TIMEOUT_EXCEEDED.value
