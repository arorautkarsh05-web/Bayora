import pytest
from fastapi import HTTPException
from backend.app.models import Role
from backend.app.isolation import WorkspaceManager
from backend.app.audit import AuditManager


def test_canary_tokens_initialization(tmp_path):
    """Canaries are placed in isolated workspaces and tracked in registry."""
    mgr = WorkspaceManager()
    tokens = mgr.get_canary_tokens()
    assert len(tokens) >= 3

    token_ids = [t.token_id for t in tokens]
    assert "canary-red-payload-01" in token_ids
    assert "canary-blue-policy-01" in token_ids
    assert "canary-model-endpoint-01" in token_ids

    # Each canary has a sha256 token_hash
    for t in tokens:
        assert len(t.token_hash) == 64
        # File exists in target workspace
        target_dir = {
            "red_team": mgr.red_dir,
            "blue_team": mgr.blue_dir,
            "model": mgr.model_dir,
        }[t.workspace_location]
        assert (target_dir / t.file_name).exists()


def test_canary_probe_blocked_and_tripped():
    """Requirement 2: Cross-team attempt to access canary is blocked and records trip."""
    mgr = WorkspaceManager()

    # Blue team attempting to read Red Team canary payload
    with pytest.raises(HTTPException) as exc_info:
        mgr.get_test_case("canary_red_payload", caller_role=Role.BLUE_TEAM, caller_user="blue_prober")

    assert exc_info.value.status_code == 403

    # Check trip events
    trips = mgr.get_canary_trips()
    assert len(trips) > 0
    latest_trip = trips[-1]
    assert latest_trip.token_id == "canary-red-payload-01"
    assert latest_trip.attempted_by_role == Role.BLUE_TEAM
    assert latest_trip.blocked is True


def test_canary_secrets_never_leak_in_audit_logs():
    """Requirement 2: Token secrets must never appear in logs or audit trail (fingerprint only)."""
    mgr = WorkspaceManager()
    trip_event = mgr.trip_canary(
        token_id="canary-blue-policy-01",
        caller_role=Role.RED_TEAM,
        caller_user="red_recon_agent",
        target_workspace="blue_team",
    )

    assert trip_event.blocked is True

    # Inspect all audit events
    from backend.app.audit import audit_mgr
    events = audit_mgr.read_events()
    matching_events = [
        e for e in events
        if e.event_type == "canary_trip_detected" and e.payload.get("trip_id") == trip_event.trip_id
    ]

    assert len(matching_events) >= 1
    audit_ev = matching_events[0]

    # Verify SHA-256 fingerprint is present
    assert "token_fingerprint" in audit_ev.payload
    assert len(audit_ev.payload["token_fingerprint"]) == 64

    # Strict assertion: NO raw fake secret string in event payload or serialized string
    event_str = str(audit_ev.model_dump())
    assert "FAKE-CANARY-TOKEN" not in event_str


def test_canary_tokens_hidden_from_standard_test_listings():
    """Canaries do not pollute ordinary test listings or evaluation suites."""
    mgr = WorkspaceManager()
    test_cases = mgr.list_test_cases(Role.OPERATOR)
    for tc in test_cases:
        assert "canary" not in tc.id.lower()
        assert not getattr(tc, "is_canary", False)
