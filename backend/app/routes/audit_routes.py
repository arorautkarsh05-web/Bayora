import json
import shutil
from typing import List, Optional, Dict, Any
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from ..models import Role, AuditEvent, AuditVerificationResult
from ..auth import get_current_user, require_role
from ..audit import audit_mgr, AUDIT_LOG_FILE

router = APIRouter(prefix="/api/audit", tags=["Audit Integrity & Verification"])

BACKUP_LOG_FILE = AUDIT_LOG_FILE.parent / "audit_chain_backup.jsonl"


class TamperDemoRequest(BaseModel):
    action: str  # "tamper_payload", "delete_event", "restore_clean"
    target_event_index: Optional[int] = None
    tampered_field: Optional[str] = "payload"
    tampered_value: Optional[str] = "MALICIOUS_ADVERSARIAL_INJECTION"


@router.get("/events", response_model=List[AuditEvent])
def list_audit_events(
    run_id: Optional[str] = Query(default=None),
    user: dict = Depends(get_current_user),
):
    """Retrieves immutable append-only audit events."""
    events = audit_mgr.read_events()
    if run_id:
        events = [e for e in events if e.run_id == run_id]
    return events


@router.get("/verify", response_model=AuditVerificationResult)
def verify_audit_trail(user: dict = Depends(get_current_user)):
    """Performs full cryptographic verification of the SHA-256 hash chain (PR-5)."""
    return audit_mgr.verify_chain()


@router.get("/public-key")
def get_public_key(user: dict = Depends(get_current_user)):
    """Returns the Ed25519 public key and SHA-256 fingerprint for independent verification."""
    return {
        "algorithm": "Ed25519",
        "fingerprint_sha256": audit_mgr.get_public_key_fingerprint(),
        "public_key_pem": audit_mgr.get_public_key_pem(),
    }


@router.post("/tamper-demo")
def inject_tampering_demo(
    req: TamperDemoRequest,
    user: dict = Depends(require_role([Role.OPERATOR, Role.REVIEWER])),
):
    """Controlled fixture to demonstrate tamper detection (PR-5).
    Allows modifying or deleting a stored event, then verifying that the hash chain breaks.
    """
    if not AUDIT_LOG_FILE.exists():
        raise HTTPException(status_code=400, detail="Audit log is empty. Run an evaluation first.")

    events = audit_mgr.read_events()
    if not events:
        raise HTTPException(status_code=400, detail="No audit events available to tamper with.")

    # 1. Backup if not already backed up
    if not BACKUP_LOG_FILE.exists():
        shutil.copyfile(AUDIT_LOG_FILE, BACKUP_LOG_FILE)

    if req.action == "restore_clean":
        if BACKUP_LOG_FILE.exists():
            shutil.copyfile(BACKUP_LOG_FILE, AUDIT_LOG_FILE)
            return {
                "status": "restored",
                "message": "Clean audit chain restored from backup.",
                "total_events": len(audit_mgr.read_events()),
            }
        else:
            return {"status": "ok", "message": "Log was already clean."}

    # Always ensure clean backup exists before mutating
    shutil.copyfile(AUDIT_LOG_FILE, BACKUP_LOG_FILE)

    idx = req.target_event_index if req.target_event_index is not None else (len(events) // 2)
    idx = max(0, min(idx, len(events) - 1))

    if req.action == "tamper_payload":
        # Modify the event payload without updating the hash
        target = events[idx]
        target.payload["_tampered_flag"] = req.tampered_value
        target.payload["tampered_timestamp"] = "2026-10-04T00:00:00Z"

        # Write back corrupted line
        with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev.model_dump()) + "\n")

        return {
            "status": "tampered",
            "action": "tamper_payload",
            "tampered_event_index": idx,
            "tampered_event_id": target.event_id,
            "message": f"Event #{idx} payload modified without recalculating hash. Run verification to see detection.",
        }

    elif req.action == "delete_event":
        # Delete the event from the chain
        removed = events.pop(idx)

        with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev.model_dump()) + "\n")

        return {
            "status": "tampered",
            "action": "delete_event",
            "deleted_event_index": idx,
            "deleted_event_id": removed.event_id,
            "message": f"Event #{idx} removed from chain. Hash pointer linkage is now broken. Run verification to see detection.",
        }

    raise HTTPException(status_code=400, detail=f"Unknown tamper action '{req.action}'")


class CheckpointCreateRequest(BaseModel):
    description: Optional[str] = "Periodic Trust Anchor Checkpoint"


@router.post("/checkpoints")
def create_checkpoint_endpoint(
    req: CheckpointCreateRequest,
    user: dict = Depends(require_role([Role.OPERATOR])),
):
    """Anchors the current audit hash chain tip into an external cryptographic checkpoint."""
    checkpoint = audit_mgr.create_checkpoint(description=req.description or "External Trust Anchor")
    return checkpoint.model_dump()


@router.get("/checkpoints")
def list_checkpoints_endpoint(user: dict = Depends(get_current_user)):
    """Lists external cryptographic checkpoints."""
    return [c.model_dump() for c in audit_mgr.list_checkpoints()]


@router.post("/checkpoints/{checkpoint_id}/verify")
def verify_checkpoint_endpoint(
    checkpoint_id: str,
    user: dict = Depends(get_current_user),
):
    """Verifies that an external checkpoint's tip hash and Merkle root match the current chain."""
    checkpoints = audit_mgr.list_checkpoints()
    target = next((c for c in checkpoints if c.checkpoint_id == checkpoint_id), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Checkpoint '{checkpoint_id}' not found")
    return audit_mgr.verify_checkpoint(target)


@router.post("/rotate-keys")
def rotate_keys_endpoint(
    user: dict = Depends(require_role([Role.OPERATOR])),
):
    """Rotates the Ed25519 signing keypair and logs the rotation event to the audit chain."""
    return audit_mgr.rotate_signing_keys(actor=user["user_id"])

