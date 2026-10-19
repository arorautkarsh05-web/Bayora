from typing import List, Dict, Any
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status
from ..models import Role, CanaryToken, CanaryTripEvent
from ..auth import get_current_user, require_role
from ..isolation import workspace_mgr, AccessBoundaryViolation
from ..audit import audit_mgr

router = APIRouter(prefix="/api/canaries", tags=["Canary Secrets & Probing Detection"])


class SimulateTripRequest(BaseModel):
    token_id: str = "canary-red-payload-01"
    simulated_role: Role = Role.BLUE_TEAM


@router.get("", response_model=List[CanaryToken])
def list_canary_tokens(user: dict = Depends(get_current_user)):
    """Lists synthetic canary tokens across isolated test workspaces.
    Does NOT expose raw fake secrets or sensitive tokens in logs or responses (Requirement 2).
    """
    return workspace_mgr.get_canary_tokens()


@router.get("/trips", response_model=List[CanaryTripEvent])
def list_canary_trips(user: dict = Depends(get_current_user)):
    """Lists recorded canary trip attempts. Shows unauthorized probes blocked by the system."""
    return workspace_mgr.get_canary_trips()


@router.post("/simulate-trip")
def simulate_canary_trip(
    req: SimulateTripRequest,
    user: dict = Depends(require_role([Role.OPERATOR])),
):
    """Simulates an unauthorized cross-team probe on a canary secret to demonstrate trip detection (Requirement 2).
    Records attempt in the tamper-evident audit trail with SHA-256 fingerprint only.
    """
    tokens = {t.token_id: t for t in workspace_mgr.get_canary_tokens()}
    if req.token_id not in tokens:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Canary token '{req.token_id}' not found",
        )

    target_tok = tokens[req.token_id]
    target_workspace = target_tok.workspace_location

    trip_event = workspace_mgr.trip_canary(
        token_id=req.token_id,
        caller_role=req.simulated_role,
        caller_user=f"simulated-attacker-{req.simulated_role.value}",
        target_workspace=target_workspace,
    )

    return {
        "status": "CANARY_TRIP_RECORDED_AND_BLOCKED",
        "trip_event": trip_event,
        "detail": f"Unauthorized probe by role '{req.simulated_role.value}' into '{target_workspace}' was blocked and recorded.",
        "token_fingerprint": target_tok.token_hash,
    }
