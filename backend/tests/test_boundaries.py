import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.models import Role
from backend.app.isolation import workspace_mgr
from backend.app.config import ORCHESTRATOR_INTERNAL_SECRET

client = TestClient(app)


def test_blue_team_cannot_read_red_team_cases():
    """PR-2 Negative Test: Blue team must be strictly blocked from reading Red Team test cases."""
    response = client.get(
        "/api/red-team/test-cases",
        headers={"X-Bayora-Role": "blue_team", "X-Bayora-User": "blue_tester_1"},
    )
    assert response.status_code == 403
    assert "Blue team cannot list Red Team test suite" in response.json()["detail"]


def test_red_team_cannot_read_blue_team_policies():
    """PR-2 Negative Test: Red team must be strictly blocked from inspecting Blue Team defense rules."""
    response = client.get(
        "/api/blue-team/policies",
        headers={"X-Bayora-Role": "red_team", "X-Bayora-User": "red_attacker_1"},
    )
    assert response.status_code == 403
    assert "Red team cannot list Blue Team defense configurations" in response.json()["detail"]


def test_path_traversal_is_blocked():
    """Negative Test: Directory traversal attempts must be caught and blocked."""
    with pytest.raises(Exception) as exc_info:
        workspace_mgr._resolve_safe_path(workspace_mgr.red_dir, "../../../windows/system32")
    assert "Illegal path traversal attempt" in str(exc_info.value)


def test_tenant_cannot_call_internal_model_endpoint():
    """PR-3 Negative Test: Tenant cannot bypass orchestrator and call internal model endpoint."""
    response = client.post(
        "/api/eval/internal/model/evaluate",
        headers={"X-Bayora-Role": "red_team", "X-Bayora-User": "red_user"},
        json={"prompt": "test prompt", "category": "adversarial"},
    )
    assert response.status_code == 403
    assert "Direct tenant access to model service is forbidden" in response.json()["detail"]


def test_orchestrator_token_permits_internal_model_call():
    """PR-3 Positive Test: Only requests with orchestrator internal token can invoke model endpoint."""
    response = client.post(
        "/api/eval/internal/model/evaluate",
        headers={
            "X-Bayora-Role": "operator",
            "X-Bayora-User": "orchestrator",
            "X-Bayora-Internal-Secret": ORCHESTRATOR_INTERNAL_SECRET,
        },
        json={"prompt": "Benign question", "category": "benign"},
    )
    assert response.status_code == 200
    assert response.json()["passed_safety_gate"] is True
