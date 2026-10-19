from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from ..models import Role, DefensivePolicy
from ..auth import get_current_user, require_role
from ..isolation import workspace_mgr

router = APIRouter(prefix="/api/blue-team", tags=["Blue Team Workspace"])


@router.get("/policies", response_model=List[DefensivePolicy])
def list_policies(user: dict = Depends(get_current_user)):
    """Lists defensive policies in Blue Team workspace. Strictly blocked for Red Team."""
    return workspace_mgr.list_policies(user["role"])


@router.post("/policies", response_model=DefensivePolicy)
def create_policy(
    policy: DefensivePolicy,
    user: dict = Depends(require_role([Role.BLUE_TEAM, Role.OPERATOR])),
):
    """Saves a defensive policy into the isolated Blue Team storage namespace."""
    policy.author = user["user_id"]
    return workspace_mgr.save_policy(policy, user["role"])


@router.get("/policies/{policy_id}", response_model=DefensivePolicy)
def get_policy(policy_id: str, user: dict = Depends(get_current_user)):
    """Retrieves a single defensive policy. Strictly denied for Red Team."""
    return workspace_mgr.get_policy(policy_id, user["role"])


@router.patch("/policies/{policy_id}/toggle", response_model=DefensivePolicy)
def toggle_policy(
    policy_id: str,
    user: dict = Depends(require_role([Role.BLUE_TEAM, Role.OPERATOR])),
):
    """Toggles active status of a defensive policy."""
    policy = workspace_mgr.get_policy(policy_id, user["role"])
    policy.is_active = not policy.is_active
    return workspace_mgr.save_policy(policy, user["role"])
