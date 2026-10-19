import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.models import Role, CheckpointAnchor
from backend.app.auth import create_signed_token
from backend.app import config, auth
from backend.app.audit import CheckpointStorageAdapter, LocalFileCheckpointAdapter, AuditManager

client = TestClient(app)


# -------------------------------------------------------------
# 1. CORS Allowlist Tests
# -------------------------------------------------------------
def test_cors_allowed_origin_header():
    """CORS: Permitted local development origin receives Access-Control-Allow-Origin."""
    response = client.options(
        "/api/auth/roles",
        headers={
            "Origin": "http://127.0.0.1:8000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") == "http://127.0.0.1:8000"


def test_cors_disallowed_origin_header():
    """CORS: Arbitrary/malicious origin does NOT receive credentialed allow-origin."""
    response = client.options(
        "/api/auth/roles",
        headers={
            "Origin": "http://malicious-attacker.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") != "http://malicious-attacker.com"


# -------------------------------------------------------------
# 2. Strict Authentication Tests
# -------------------------------------------------------------
def test_strict_auth_valid_bearer_token(monkeypatch):
    """Strict Auth: Valid cryptographic Bearer token is accepted."""
    monkeypatch.setattr(auth, "BAYORA_STRICT_AUTH", True)
    token = create_signed_token(user_id="strict-user", role=Role.REVIEWER)
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == "strict-user"
    assert data["role"] == "reviewer"
    assert data["auth_mode"] == "cryptographic_bearer"


def test_strict_auth_missing_token_rejected_even_with_headers(monkeypatch):
    """Strict Auth: Missing Bearer token returns 401 even if X-Bayora-Role is provided (Anti-Spoofing)."""
    monkeypatch.setattr(auth, "BAYORA_STRICT_AUTH", True)
    response = client.get(
        "/api/auth/me",
        headers={"X-Bayora-Role": "operator", "X-Bayora-User": "unauthorized-spoofed-operator"},
    )
    assert response.status_code == 401
    assert "Strict authentication required" in response.json()["detail"]


def test_strict_auth_invalid_token_rejected(monkeypatch):
    """Strict Auth: Tampered or forged Bearer token returns 401."""
    monkeypatch.setattr(auth, "BAYORA_STRICT_AUTH", True)
    valid_token = create_signed_token(user_id="strict-user", role=Role.REVIEWER)
    parts = valid_token.split(".")
    tampered_token = f"{parts[0]}.{parts[1][:-4]}XXXX.{parts[2]}"
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert response.status_code == 401


def test_strict_auth_malformed_scheme_rejected(monkeypatch):
    """Strict Auth: Non-Bearer authorization scheme returns 401."""
    monkeypatch.setattr(auth, "BAYORA_STRICT_AUTH", True)
    response = client.get("/api/auth/me", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code == 401
    assert "Invalid authorization scheme" in response.json()["detail"]


# -------------------------------------------------------------
# 3. Demo / Non-Strict Mode Backward Compatibility Tests
# -------------------------------------------------------------
def test_demo_mode_valid_role_header(monkeypatch):
    """Demo Mode: Valid X-Bayora-Role is supported when strict auth is disabled."""
    monkeypatch.setattr(auth, "BAYORA_STRICT_AUTH", False)
    response = client.get(
        "/api/auth/me",
        headers={"X-Bayora-Role": "reviewer", "X-Bayora-User": "demo-reviewer"},
    )
    assert response.status_code == 200
    assert response.json()["role"] == "reviewer"
    assert response.json()["auth_mode"] == "header_simulation"


def test_demo_mode_missing_credentials_returns_401(monkeypatch):
    """Demo Mode: Unauthenticated request without token or role header returns 401 (never defaults to operator)."""
    monkeypatch.setattr(auth, "BAYORA_STRICT_AUTH", False)
    response = client.get("/api/auth/me")
    assert response.status_code == 401


# -------------------------------------------------------------
# 4. Checkpoint Storage Adapter Boundary Tests
# -------------------------------------------------------------
class InMemoryCheckpointAdapter(CheckpointStorageAdapter):
    def __init__(self):
        self.checkpoints = []

    def save_checkpoint(self, anchor: CheckpointAnchor) -> None:
        self.checkpoints.append(anchor)

    def load_checkpoints(self):
        return list(self.checkpoints)


def test_checkpoint_storage_adapter_interface():
    """Audit Architecture: Pluggable storage adapter interface successfully persists and loads checkpoints."""
    in_memory = InMemoryCheckpointAdapter()
    mgr = AuditManager(checkpoint_adapter=in_memory)
    ckpt = mgr.create_checkpoint(description="Adapter Test Checkpoint")
    assert ckpt.checkpoint_id.startswith("ckpt_")
    loaded = mgr.list_checkpoints()
    assert len(loaded) == 1
    assert loaded[0].checkpoint_id == ckpt.checkpoint_id
