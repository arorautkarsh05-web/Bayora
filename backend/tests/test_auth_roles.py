import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_missing_role_header_unauthorized():
    """PR-1: Missing auth role returns 401 Unauthorized."""
    response = client.get("/api/auth/me", headers={"X-Bayora-Role": ""})
    assert response.status_code == 401


def test_invalid_role_forbidden():
    """PR-1: Unknown role returns 403 Forbidden."""
    response = client.get("/api/auth/me", headers={"X-Bayora-Role": "superadmin_hacker"})
    assert response.status_code == 403


def test_reviewer_cannot_create_runs():
    """PR-1: Reviewer role is read-only and cannot trigger evaluation runs."""
    response = client.post(
        "/api/eval/runs",
        headers={"X-Bayora-Role": "reviewer", "X-Bayora-User": "auditor_alice"},
        json={"name": "Unauthorized Run", "model_id": "mock"},
    )
    assert response.status_code == 403
    assert "Access denied" in response.json()["detail"]


def test_red_team_cannot_create_runs():
    """PR-1: Red team participants cannot trigger orchestrator runs directly."""
    response = client.post(
        "/api/eval/runs",
        headers={"X-Bayora-Role": "red_team", "X-Bayora-User": "red_attacker"},
        json={"name": "Unauthorized Run", "model_id": "mock"},
    )
    assert response.status_code == 403


def test_unauthenticated_request_no_headers_returns_401():
    """Security Regression: Unauthenticated requests without token or role header must return 401, not default to operator."""
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]

