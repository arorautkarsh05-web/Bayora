import asyncio
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Header, status, BackgroundTasks, Query
from fastapi.responses import PlainTextResponse, JSONResponse
from ..models import (
    Role,
    EvaluationConfig,
    EvaluationRun,
    RunManifest,
    RunComparisonResult,
    EvidenceReport,
)
from ..auth import get_current_user, require_role
from ..orchestrator import orchestrator
from ..audit import audit_mgr
from ..isolation import workspace_mgr
from ..mock_model import mock_model_service

router = APIRouter(prefix="/api/eval", tags=["Evaluation & Orchestration"])


@router.get("/runs", response_model=List[EvaluationRun])
def list_runs(user: dict = Depends(get_current_user)):
    """Lists all evaluation runs. Available to Operator and Reviewer."""
    return orchestrator.list_runs()


@router.get("/runs/{run_id}", response_model=EvaluationRun)
def get_run(run_id: str, user: dict = Depends(get_current_user)):
    """Retrieves detailed status and test breakdowns of a run."""
    run = orchestrator.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
    return run


@router.post("/runs", response_model=EvaluationRun)
async def create_and_start_run(
    config: EvaluationConfig,
    user: dict = Depends(require_role([Role.OPERATOR])),
):
    """Creates and starts an evaluation run (Operator role required)."""
    run = orchestrator.create_run(config, operator_id=user["user_id"])
    # Run evaluation
    run = await orchestrator.execute_run(run.id, config)
    return run


@router.post("/runs/{run_id}/cancel", response_model=EvaluationRun)
def cancel_run(
    run_id: str,
    user: dict = Depends(require_role([Role.OPERATOR])),
):
    """Cancels an in-progress evaluation run."""
    run = orchestrator.cancel_run(run_id, operator_id=user["user_id"])
    if not run:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
    return run


@router.get("/runs/{run_id}/manifest", response_model=RunManifest)
def get_run_manifest(run_id: str, user: dict = Depends(get_current_user)):
    """Exports an Ed25519-signed run manifest (PR-8). Sensitive prompts remain hashed."""
    manifest = orchestrator.get_run_manifest(run_id)
    if not manifest:
        raise HTTPException(
            status_code=404,
            detail=f"Manifest for completed run '{run_id}' not available",
        )
    return manifest


@router.post("/runs/{run_id}/verify-manifest")
def verify_manifest(run_id: str, user: dict = Depends(get_current_user)):
    """Verifies the Ed25519 cryptographic signature of a run manifest (PR-8)."""
    manifest = orchestrator.get_run_manifest(run_id)
    if not manifest:
        raise HTTPException(
            status_code=404,
            detail=f"Run '{run_id}' does not have a signed manifest yet",
        )

    manifest_dict = {
        "manifest_version": manifest.manifest_version,
        "run_id": manifest.run_id,
        "run_name": manifest.run_name,
        "model_id": manifest.model_id,
        "policy_id": manifest.policy_id,
        "total_tests": manifest.total_tests,
        "outcome_summary": manifest.outcome_summary,
        "test_fingerprints": manifest.test_fingerprints,
        "started_at": manifest.started_at,
        "completed_at": manifest.completed_at,
        "start_event_hash": manifest.start_event_hash,
        "end_event_hash": manifest.end_event_hash,
    }

    is_valid = audit_mgr.verify_manifest_signature(manifest_dict, manifest.signature)
    return {
        "run_id": run_id,
        "is_signature_valid": is_valid,
        "signer_public_key_fingerprint": manifest.public_key_fingerprint,
        "manifest_signature": manifest.signature,
        "verified_at": manifest.completed_at,
    }


# ================= Internal Model Service Interface (PR-3) =================
@router.post("/internal/model/evaluate")
async def internal_model_eval(
    payload: Dict[str, Any],
    x_bayora_internal_secret: Optional[str] = Header(default=None),
    user: dict = Depends(get_current_user),
):
    """Direct model evaluation endpoint. Accessible ONLY to orchestrator with secret token! (PR-3)"""
    workspace_mgr.verify_orchestrator_token(x_bayora_internal_secret, user["role"])
    res = await mock_model_service.evaluate_prompt(
        prompt=payload.get("prompt", ""),
        category=payload.get("category", "adversarial"),
    )
    return res


# ================= Repeatable Evaluations & Comparison (PR-5) =================
class CompareRunsRequest(BaseModel):
    baseline_run_id: str
    rerun_run_id: str


@router.post("/runs/{run_id}/rerun", response_model=EvaluationRun)
async def rerun_evaluation(
    run_id: str,
    user: dict = Depends(require_role([Role.OPERATOR])),
):
    """Reruns the exact test configuration of an existing baseline run (Requirement 5)."""
    try:
        rerun = await orchestrator.rerun_run(run_id, operator_id=user["user_id"])
        return rerun
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/runs/compare", response_model=RunComparisonResult)
def compare_evaluations(
    req: CompareRunsRequest,
    user: dict = Depends(get_current_user),
):
    """Compares baseline vs rerun evaluation results test-by-test with reproducibility delta (Requirement 5)."""
    try:
        return orchestrator.compare_runs(req.baseline_run_id, req.rerun_run_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ================= Evidence Report Generation (PR-6) =================
@router.get("/runs/{run_id}/evidence-report")
def export_evidence_report(
    run_id: str,
    format: str = Query("json", pattern="^(json|markdown)$"),
    user: dict = Depends(get_current_user),
):
    """Exports a tamper-evident evidence report containing run metadata, security checks, and limitations (Requirement 6)."""
    try:
        result = orchestrator.generate_evidence_report(run_id, format_type=format)
        if format == "markdown":
            return PlainTextResponse(content=result, media_type="text/markdown")
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

