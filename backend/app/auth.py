import base64
import hashlib
import hmac
import json
import time
from typing import List, Optional, Dict, Any
from fastapi import Header, HTTPException, status, Depends

from .models import Role
from .config import AUTH_TOKEN_SECRET, MAX_CONCURRENT_EVALS_PER_ROLE, BAYORA_STRICT_AUTH
from .audit import audit_mgr


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data_str: str) -> bytes:
    padding = "=" * ((4 - len(data_str) % 4) % 4)
    return base64.urlsafe_b64decode(data_str + padding)


def create_signed_token(user_id: str, role: Role, expires_in_seconds: int = 7200) -> str:
    """Generates a cryptographically signed HMAC-SHA256 session bearer token."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": user_id,
        "role": role.value if isinstance(role, Role) else str(role),
        "iat": now,
        "exp": now + expires_in_seconds,
        "iss": "bayora-auth-authority",
    }
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(AUTH_TOKEN_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_signed_token(token: str) -> Dict[str, Any]:
    """Cryptographically verifies a signed bearer token, checking signature and expiration."""
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed bearer authentication token format",
        )
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(AUTH_TOKEN_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    actual_sig = _b64url_decode(sig_b64)

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cryptographic bearer token signature verification failed (Tampered Token)",
        )

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unparseable token claims body",
        )

    now = int(time.time())
    if payload.get("exp", 0) < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Bearer authentication token expired at {payload.get('exp')}",
        )

    return payload


# In-memory Concurrency & Quota Tracker
class QuotaManager:
    def __init__(self):
        self._active_runs_per_role: Dict[str, int] = {}

    def acquire_run_slot(self, role: Role) -> bool:
        r_val = role.value
        current = self._active_runs_per_role.get(r_val, 0)
        if current >= MAX_CONCURRENT_EVALS_PER_ROLE:
            return False
        self._active_runs_per_role[r_val] = current + 1
        return True

    def release_run_slot(self, role: Role):
        r_val = role.value
        if r_val in self._active_runs_per_role and self._active_runs_per_role[r_val] > 0:
            self._active_runs_per_role[r_val] -= 1


quota_mgr = QuotaManager()


def get_current_user(
    authorization: Optional[str] = Header(default=None),
    x_bayora_user: Optional[str] = Header(default=None),
    x_bayora_role: Optional[str] = Header(default=None),
) -> dict:
    """Extracts authenticated identity.
    Priority 1: Cryptographically signed Bearer Token (Authorization: Bearer <token>)
    Priority 2: Header-based demo/test identity ONLY when BAYORA_STRICT_AUTH is False.
    Unauthenticated requests (neither token nor demo header) are strictly rejected with 401.
    """
    # 1. Check for cryptographic Bearer Token
    if authorization:
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization scheme. 'Authorization: Bearer <token>' is required.",
            )
        token_str = authorization[7:].strip()
        if not token_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer authentication token cannot be empty.",
            )
        claims = verify_signed_token(token_str)
        try:
            role_enum = Role(claims["role"].lower())
        except (KeyError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token contains invalid or missing role claim.",
            )
        return {
            "user_id": claims.get("sub", "unknown-subject"),
            "role": role_enum,
            "auth_mode": "cryptographic_bearer",
            "token_claims": claims,
        }

    # 2. If Strict Auth is enforced, reject any request missing a Bearer token
    if BAYORA_STRICT_AUTH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Strict authentication required. Missing valid 'Authorization: Bearer <token>' header.",
        )

    # 3. Non-Strict Demo Mode: Check for explicit X-Bayora-Role
    if not x_bayora_role or not x_bayora_role.strip():
        # NEVER assign 'operator' to unauthenticated requests
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide 'Authorization: Bearer <token>' or specify demo role via 'X-Bayora-Role'.",
        )

    try:
        role_enum = Role(x_bayora_role.strip().lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Invalid role '{x_bayora_role}'. Permitted roles: {[r.value for r in Role]}",
        )

    user_id = (x_bayora_user or f"user-{role_enum.value}").strip()
    return {
        "user_id": user_id,
        "role": role_enum,
        "auth_mode": "header_simulation",
    }


def require_role(allowed_roles: List[Role]):
    """FastAPI dependency to enforce role-based access control (PR-1)."""
    def dependency(user: dict = Depends(get_current_user)):
        user_role = user["role"]
        if user_role not in allowed_roles:
            audit_mgr.append_event(
                actor=user["user_id"],
                role=user_role,
                event_type="access_denied",
                payload={
                    "attempted_role": user_role.value,
                    "required_roles": [r.value for r in allowed_roles],
                    "auth_mode": user.get("auth_mode", "unknown"),
                    "reason": "Insufficient role permissions",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Role '{user_role.value}' cannot perform this action. Required: {[r.value for r in allowed_roles]}",
            )
        return user

    return dependency
