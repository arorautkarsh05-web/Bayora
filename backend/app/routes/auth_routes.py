from typing import Dict, Any, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from ..models import Role
from ..auth import get_current_user, create_signed_token, verify_signed_token

router = APIRouter(prefix="/api/auth", tags=["Authentication & Identity"])


class TokenRequest(BaseModel):
    user_id: str
    role: Role
    expires_in_seconds: Optional[int] = 7200


class TokenVerifyRequest(BaseModel):
    token: str


@router.get("/me")
def get_user_profile(user: dict = Depends(get_current_user)):
    """Returns the authenticated identity, role, auth mode, and permitted operations."""
    role = user["role"]
    permissions = {
        Role.OPERATOR: [
            "create_run",
            "cancel_run",
            "view_all_workspaces",
            "export_manifest",
            "verify_audit",
            "run_security_tests",
        ],
        Role.RED_TEAM: [
            "read_red_workspace",
            "write_red_workspace",
            "submit_test_cases",
        ],
        Role.BLUE_TEAM: [
            "read_blue_workspace",
            "write_blue_workspace",
            "configure_policies",
        ],
        Role.REVIEWER: [
            "view_runs",
            "view_manifests",
            "verify_manifest_signature",
            "verify_audit_chain",
            "view_threat_model",
            "run_security_tests",
        ],
    }

    return {
        "user_id": user["user_id"],
        "role": role.value,
        "auth_mode": user.get("auth_mode", "header_simulation"),
        "permissions": permissions.get(role, []),
    }


@router.post("/token")
def issue_access_token(req: TokenRequest) -> Dict[str, Any]:
    """Issues a cryptographically signed HMAC-SHA256 bearer session token."""
    token = create_signed_token(
        user_id=req.user_id,
        role=req.role,
        expires_in_seconds=req.expires_in_seconds or 7200,
    )
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": req.expires_in_seconds or 7200,
        "role": req.role.value,
        "user_id": req.user_id,
    }


@router.post("/verify-token")
def verify_token_endpoint(req: TokenVerifyRequest) -> Dict[str, Any]:
    """Verifies cryptographic signature and expiration of a bearer token."""
    claims = verify_signed_token(req.token)
    return {
        "valid": True,
        "claims": claims,
    }


@router.get("/roles")
def get_available_roles():
    """Lists supported platform roles for demo simulation."""
    return [
        {
            "id": Role.OPERATOR.value,
            "title": "Evaluator / Operator",
            "description": "Orchestrates evaluations, inspects runs, and exports signed evidence manifests.",
        },
        {
            "id": Role.RED_TEAM.value,
            "title": "Red Team Participant",
            "description": "Submits adversarial payloads to isolated red workspace; cannot inspect blue policies or model credentials.",
        },
        {
            "id": Role.BLUE_TEAM.value,
            "title": "Blue Team Participant",
            "description": "Defines defensive guardrail rules; cannot inspect unreleased red-team attack payloads.",
        },
        {
            "id": Role.REVIEWER.value,
            "title": "Reviewer / Auditor",
            "description": "Verifies cryptographic audit integrity, Ed25519 signatures, and checks threat model guarantees.",
        },
    ]
