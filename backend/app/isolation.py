import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import HTTPException, status

from .config import (
    WORKSPACES_DIR,
    RED_TEAM_DIR,
    BLUE_TEAM_DIR,
    MODEL_DIR,
    CANARIES_DIR,
    ORCHESTRATOR_INTERNAL_SECRET,
    MAX_PAYLOAD_BYTES,
)
from .models import Role, TestCase, DefensivePolicy, CanaryToken, CanaryTripEvent
from .audit import audit_mgr


class AccessBoundaryViolation(HTTPException):
    def __init__(self, detail: str, source_role: Role, target_namespace: str, canary_tripped: bool = False):
        event_type = "canary_trip_blocked" if canary_tripped else "boundary_violation_blocked"
        # Audit boundary violation attempt
        audit_mgr.append_event(
            actor=f"tenant-{source_role.value}",
            role=source_role,
            event_type=event_type,
            payload={
                "source_role": source_role.value,
                "target_namespace": target_namespace,
                "violation_detail": detail,
                "canary_tripped": canary_tripped,
            },
        )
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Workload boundary violation blocked: {detail}",
        )


class WorkspaceManager:
    """Enforces strict storage namespace separation between Red Team, Blue Team, and Model workloads."""

    def __init__(self):
        self.red_dir = RED_TEAM_DIR
        self.blue_dir = BLUE_TEAM_DIR
        self.model_dir = MODEL_DIR
        self.canaries_dir = CANARIES_DIR
        self.canaries_meta_file = self.canaries_dir / "canaries_registry.json"
        self.trips_file = self.canaries_dir / "canary_trips.json"
        self._initialize_canaries()

    def _hash_canary(self, secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def _initialize_canaries(self):
        """Places clearly fake, unique canary tokens in isolated workspaces (Requirement 2)."""
        canary_defs = [
            {
                "token_id": "canary-red-payload-01",
                "name": "Red Team Confidential Payload Canary",
                "workspace_location": "red_team",
                "file_name": "canary_red_payload.json",
                "description": "Fake canary payload placed in red-team workspace to detect snooping by blue-team",
                "fake_secret": "FAKE-CANARY-TOKEN-RED-TEAM-DO-NOT-LEAK-7a91bf",
                "target_dir": self.red_dir,
            },
            {
                "token_id": "canary-blue-policy-01",
                "name": "Blue Team Guardrail Canary Key",
                "workspace_location": "blue_team",
                "file_name": "canary_blue_classifier.json",
                "description": "Fake canary classifier rule placed in blue-team workspace to detect reconnaissance by red-team",
                "fake_secret": "FAKE-CANARY-TOKEN-BLUE-TEAM-CLASSIFIER-DO-NOT-LEAK-3c82d4",
                "target_dir": self.blue_dir,
            },
            {
                "token_id": "canary-model-endpoint-01",
                "name": "Model Internal Service Canary",
                "workspace_location": "model",
                "file_name": "canary_model_access.json",
                "description": "Fake model credential canary to detect tenant attempts to read model state",
                "fake_secret": "FAKE-CANARY-TOKEN-MODEL-INTERNAL-CREDENTIAL-9e120a",
                "target_dir": self.model_dir,
            },
        ]

        registry: Dict[str, Dict[str, Any]] = {}
        now = datetime.now(timezone.utc).isoformat()

        for c in canary_defs:
            f_path = c["target_dir"] / c["file_name"]
            token_hash = self._hash_canary(c["fake_secret"])

            if not f_path.exists():
                # Write clearly fake decoy data with canary marker
                content = {
                    "is_canary": True,
                    "notice": "THIS IS A SYNTHETIC SECURITY CANARY TOKEN. DO NOT USE IN PRODUCTION.",
                    "canary_id": c["token_id"],
                    "fingerprint_sha256": token_hash,
                    "created_at": now,
                }
                f_path.write_text(json.dumps(content, indent=2), encoding="utf-8")

            registry[c["token_id"]] = {
                "token_id": c["token_id"],
                "name": c["name"],
                "workspace_location": c["workspace_location"],
                "file_name": c["file_name"],
                "description": c["description"],
                "token_hash": token_hash,
                "created_at": now,
                "tripped": False,
                "trip_count": 0,
                "last_tripped_at": None,
            }

        # Keep existing trip history if file already exists
        if not self.canaries_meta_file.exists():
            self.canaries_meta_file.write_text(json.dumps(registry, indent=2), encoding="utf-8")

        if not self.trips_file.exists():
            self.trips_file.write_text("[]", encoding="utf-8")

    def get_canary_tokens(self) -> List[CanaryToken]:
        """Returns all canary token definitions (without exposing raw fake secrets)."""
        if not self.canaries_meta_file.exists():
            return []
        try:
            data = json.loads(self.canaries_meta_file.read_text(encoding="utf-8"))
            return [CanaryToken(**v) for v in data.values()]
        except Exception:
            return []

    def get_canary_trips(self) -> List[CanaryTripEvent]:
        """Returns recorded canary trip events."""
        if not self.trips_file.exists():
            return []
        try:
            data = json.loads(self.trips_file.read_text(encoding="utf-8"))
            return [CanaryTripEvent(**t) for t in data]
        except Exception:
            return []

    def trip_canary(self, token_id: str, caller_role: Role, caller_user: str, target_workspace: str) -> CanaryTripEvent:
        """Records a canary trip event without exposing token secret in logs (Requirement 2)."""
        tokens = {t.token_id: t for t in self.get_canary_tokens()}
        tok = tokens.get(token_id)
        tok_name = tok.name if tok else "Unknown Canary"
        token_hash = tok.token_hash if tok else "unknown"

        now = datetime.now(timezone.utc).isoformat()
        trip_event = CanaryTripEvent(
            trip_id=f"trip_{uuid.uuid4().hex[:8]}",
            token_id=token_id,
            token_name=tok_name,
            attempted_by_role=caller_role,
            attempted_by_user=caller_user,
            target_workspace=target_workspace,
            timestamp=now,
            blocked=True,
            evidence=f"Attempted unauthorized read of isolated canary token '{token_id}' by role '{caller_role.value}'",
        )

        # Update registry
        if self.canaries_meta_file.exists():
            try:
                reg = json.loads(self.canaries_meta_file.read_text(encoding="utf-8"))
                if token_id in reg:
                    reg[token_id]["tripped"] = True
                    reg[token_id]["trip_count"] = reg[token_id].get("trip_count", 0) + 1
                    reg[token_id]["last_tripped_at"] = now
                    self.canaries_meta_file.write_text(json.dumps(reg, indent=2), encoding="utf-8")
            except Exception:
                pass

        # Append to trips file
        try:
            trips = json.loads(self.trips_file.read_text(encoding="utf-8")) if self.trips_file.exists() else []
            trips.append(trip_event.model_dump())
            self.trips_file.write_text(json.dumps(trips, indent=2), encoding="utf-8")
        except Exception:
            pass

        # Record in tamper-evident audit log with SHA-256 fingerprint ONLY (NEVER raw secret)
        audit_mgr.append_event(
            actor=caller_user,
            role=caller_role,
            event_type="canary_trip_detected",
            payload={
                "trip_id": trip_event.trip_id,
                "token_id": token_id,
                "token_fingerprint": token_hash,
                "target_workspace": target_workspace,
                "attempted_by_role": caller_role.value,
                "blocked": True,
            },
        )

        return trip_event

    def _resolve_safe_path(self, base_dir: Path, relative_path: str) -> Path:
        """Resolves path and prevents directory traversal attacks."""
        resolved = (base_dir / relative_path).resolve()
        try:
            resolved.relative_to(base_dir.resolve())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Illegal path traversal attempt: '{relative_path}'",
            )
        return resolved

    # ================= Red Team Workspace Operations =================
    def save_test_case(self, test_case: TestCase, caller_role: Role) -> TestCase:
        if caller_role not in [Role.RED_TEAM, Role.OPERATOR]:
            raise AccessBoundaryViolation(
                f"Role '{caller_role.value}' cannot write to Red Team workspace",
                source_role=caller_role,
                target_namespace="red_team",
            )

        file_path = self._resolve_safe_path(self.red_dir, f"{test_case.id}.json")
        data = test_case.model_dump()
        payload_bytes = json.dumps(data).encode("utf-8")
        if len(payload_bytes) > MAX_PAYLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Test case payload size {len(payload_bytes)} exceeds limit of {MAX_PAYLOAD_BYTES} bytes",
            )

        file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        audit_mgr.append_event(
            actor=test_case.author,
            role=caller_role,
            event_type="test_case_stored",
            payload={
                "test_id": test_case.id,
                "name": test_case.name,
                "category": test_case.category,
                "severity": test_case.severity.value,
            },
        )
        return test_case

    def get_test_case(self, test_id: str, caller_role: Role, caller_user: str = "unknown") -> TestCase:
        """Blue team CANNOT read unreleased red team test cases! (PR-2)"""
        is_canary = "canary" in test_id.lower()
        if caller_role == Role.BLUE_TEAM:
            if is_canary:
                self.trip_canary("canary-red-payload-01", caller_role=caller_role, caller_user=caller_user, target_workspace="red_team")
            raise AccessBoundaryViolation(
                "Blue team is strictly prohibited from accessing unreleased Red Team test cases or payloads",
                source_role=caller_role,
                target_namespace="red_team",
                canary_tripped=is_canary,
            )
        file_path = self._resolve_safe_path(self.red_dir, f"{test_id}.json")
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"Test case '{test_id}' not found")
        data = json.loads(file_path.read_text(encoding="utf-8"))
        return TestCase(**data)

    def list_test_cases(self, caller_role: Role) -> List[TestCase]:
        if caller_role == Role.BLUE_TEAM:
            raise AccessBoundaryViolation(
                "Blue team cannot list Red Team test suite",
                source_role=caller_role,
                target_namespace="red_team",
            )
        cases = []
        for p in self.red_dir.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                # Filter out pure canary tokens from normal test listing so they act as hidden tripwires
                if data.get("is_canary"):
                    continue
                cases.append(TestCase(**data))
            except Exception:
                continue
        return cases

    # ================= Blue Team Workspace Operations =================
    def save_policy(self, policy: DefensivePolicy, caller_role: Role) -> DefensivePolicy:
        if caller_role not in [Role.BLUE_TEAM, Role.OPERATOR]:
            raise AccessBoundaryViolation(
                f"Role '{caller_role.value}' cannot write to Blue Team workspace",
                source_role=caller_role,
                target_namespace="blue_team",
            )

        file_path = self._resolve_safe_path(self.blue_dir, f"{policy.id}.json")
        data = policy.model_dump()
        payload_bytes = json.dumps(data).encode("utf-8")
        if len(payload_bytes) > MAX_PAYLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Defensive policy size {len(payload_bytes)} exceeds limit of {MAX_PAYLOAD_BYTES} bytes",
            )

        file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        audit_mgr.append_event(
            actor=policy.author,
            role=caller_role,
            event_type="defensive_policy_updated",
            payload={
                "policy_id": policy.id,
                "name": policy.name,
                "version": policy.version,
                "rules_count": len(policy.rules),
            },
        )
        return policy

    def get_policy(self, policy_id: str, caller_role: Role, caller_user: str = "unknown") -> DefensivePolicy:
        """Red team CANNOT inspect blue team defense configurations! (PR-2)"""
        is_canary = "canary" in policy_id.lower()
        if caller_role == Role.RED_TEAM:
            if is_canary:
                self.trip_canary("canary-blue-policy-01", caller_role=caller_role, caller_user=caller_user, target_workspace="blue_team")
            raise AccessBoundaryViolation(
                "Red team is prohibited from reading Blue Team defensive policy configurations or rules",
                source_role=caller_role,
                target_namespace="blue_team",
                canary_tripped=is_canary,
            )
        file_path = self._resolve_safe_path(self.blue_dir, f"{policy_id}.json")
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"Defensive policy '{policy_id}' not found")
        data = json.loads(file_path.read_text(encoding="utf-8"))
        return DefensivePolicy(**data)

    def list_policies(self, caller_role: Role) -> List[DefensivePolicy]:
        if caller_role == Role.RED_TEAM:
            raise AccessBoundaryViolation(
                "Red team cannot list Blue Team defense configurations",
                source_role=caller_role,
                target_namespace="blue_team",
            )
        policies = []
        for p in self.blue_dir.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                # Filter out pure canary tokens from normal policy listing
                if data.get("is_canary"):
                    continue
                policies.append(DefensivePolicy(**data))
            except Exception:
                continue
        return policies

    # ================= Universal Workspace File Access Check (PR-1, PR-2) =================
    def read_workspace_file(self, workspace: str, filename: str, caller_role: Role, caller_user: str = "unknown") -> Dict[str, Any]:
        """Universal storage isolation checkpoint with canary detection."""
        target_dir = {
            "red_team": self.red_dir,
            "blue_team": self.blue_dir,
            "model": self.model_dir,
        }.get(workspace)

        if not target_dir:
            raise HTTPException(status_code=400, detail=f"Unknown workspace '{workspace}'")

        is_canary = "canary" in filename.lower()

        if workspace == "red_team" and caller_role not in [Role.RED_TEAM, Role.OPERATOR]:
            if is_canary:
                self.trip_canary("canary-red-payload-01", caller_role=caller_role, caller_user=caller_user, target_workspace="red_team")
            raise AccessBoundaryViolation(
                f"Role '{caller_role.value}' denied read access to Red Team workspace file '{filename}'",
                source_role=caller_role,
                target_namespace="red_team",
                canary_tripped=is_canary,
            )

        if workspace == "blue_team" and caller_role not in [Role.BLUE_TEAM, Role.OPERATOR]:
            if is_canary:
                self.trip_canary("canary-blue-policy-01", caller_role=caller_role, caller_user=caller_user, target_workspace="blue_team")
            raise AccessBoundaryViolation(
                f"Role '{caller_role.value}' denied read access to Blue Team workspace file '{filename}'",
                source_role=caller_role,
                target_namespace="blue_team",
                canary_tripped=is_canary,
            )

        if workspace == "model" and caller_role != Role.OPERATOR:
            if is_canary:
                self.trip_canary("canary-model-endpoint-01", caller_role=caller_role, caller_user=caller_user, target_workspace="model")
            raise AccessBoundaryViolation(
                f"Role '{caller_role.value}' denied direct file access to Model workspace '{filename}'",
                source_role=caller_role,
                target_namespace="model",
                canary_tripped=is_canary,
            )

        safe_path = self._resolve_safe_path(target_dir, filename)
        if not safe_path.exists():
            raise HTTPException(status_code=404, detail=f"File '{filename}' not found in '{workspace}'")
        return json.loads(safe_path.read_text(encoding="utf-8"))

    # ================= Orchestrator Model Endpoint Protection (PR-3) =================
    @staticmethod
    def verify_orchestrator_token(token: Optional[str], caller_role: Role):
        """Ensures ONLY the orchestrator control plane can invoke the model endpoint directly."""
        if token != ORCHESTRATOR_INTERNAL_SECRET:
            audit_mgr.append_event(
                actor=f"tenant-{caller_role.value}",
                role=caller_role,
                event_type="unauthorized_model_call_blocked",
                payload={
                    "caller_role": caller_role.value,
                    "reason": "Direct tenant access to model endpoint is forbidden. Must go through orchestrator.",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Direct tenant access to model service is forbidden. Invocations must originate from the authorized Orchestrator.",
            )


workspace_mgr = WorkspaceManager()
