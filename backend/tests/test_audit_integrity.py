import copy
import pytest
from backend.app.models import Role
from backend.app.audit import AuditManager, GENESIS_HASH


def test_audit_hash_chain_creation(tmp_path):
    log_file = tmp_path / "test_audit.jsonl"
    mgr = AuditManager(log_path=log_file)

    # Append 3 events
    e1 = mgr.append_event("operator-1", Role.OPERATOR, "init", {"meta": "1"})
    e2 = mgr.append_event("red-1", Role.RED_TEAM, "upload", {"meta": "2"})
    e3 = mgr.append_event("orchestrator", Role.OPERATOR, "run", {"meta": "3"})

    assert e1.prev_hash == GENESIS_HASH
    assert e2.prev_hash == e1.event_hash
    assert e3.prev_hash == e2.event_hash

    # Verify chain
    result = mgr.verify_chain()
    assert result.is_valid is True
    assert result.total_events == 3
    assert result.broken_link_index is None


def test_tamper_detection_modified_payload(tmp_path):
    """PR-5 Acceptance Test: Changing stored event body causes verification to fail."""
    log_file = tmp_path / "test_audit.jsonl"
    mgr = AuditManager(log_path=log_file)

    mgr.append_event("user1", Role.OPERATOR, "event1", {"safe": True})
    mgr.append_event("user2", Role.RED_TEAM, "event2", {"safe": False})
    mgr.append_event("user3", Role.OPERATOR, "event3", {"safe": True})

    events = mgr.read_events()
    assert len(events) == 3

    # Tamper with event #1
    tampered_events = copy.deepcopy(events)
    tampered_events[1].payload["safe"] = True  # Maliciously altered outcome

    result = mgr.verify_chain(tampered_events)
    assert result.is_valid is False
    assert result.broken_link_index == 1
    assert "payload was tampered with" in result.error_message


def test_tamper_detection_deleted_event(tmp_path):
    """PR-5 Acceptance Test: Deleting an event causes verification to fail due to prev_hash link break."""
    log_file = tmp_path / "test_audit.jsonl"
    mgr = AuditManager(log_path=log_file)

    mgr.append_event("user1", Role.OPERATOR, "event1", {"val": 1})
    mgr.append_event("user2", Role.OPERATOR, "event2", {"val": 2})
    mgr.append_event("user3", Role.OPERATOR, "event3", {"val": 3})

    events = mgr.read_events()
    # Delete middle event (index 1)
    tampered_events = [events[0], events[2]]

    result = mgr.verify_chain(tampered_events)
    assert result.is_valid is False
    assert result.broken_link_index == 1
    assert "does not match expected prev_hash" in result.error_message


def test_tamper_detection_reordered_events(tmp_path):
    """PR-5 Acceptance Test: Reordering events causes verification to fail."""
    log_file = tmp_path / "test_audit.jsonl"
    mgr = AuditManager(log_path=log_file)

    mgr.append_event("user1", Role.OPERATOR, "event1", {"val": 1})
    mgr.append_event("user2", Role.OPERATOR, "event2", {"val": 2})

    events = mgr.read_events()
    # Swap order
    tampered_events = [events[1], events[0]]

    result = mgr.verify_chain(tampered_events)
    assert result.is_valid is False
