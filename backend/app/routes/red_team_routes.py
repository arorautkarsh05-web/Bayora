from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from ..models import Role, TestCase
from ..auth import get_current_user, require_role
from ..isolation import workspace_mgr

router = APIRouter(prefix="/api/red-team", tags=["Red Team Workspace"])


@router.get("/test-cases", response_model=List[TestCase])
def list_test_cases(user: dict = Depends(get_current_user)):
    """Lists test cases in Red Team workspace. Strictly blocked for Blue Team."""
    return workspace_mgr.list_test_cases(user["role"])


@router.post("/test-cases", response_model=TestCase)
def create_test_case(
    test_case: TestCase,
    user: dict = Depends(require_role([Role.RED_TEAM, Role.OPERATOR])),
):
    """Submits a new test case into the isolated Red Team storage namespace."""
    test_case.author = user["user_id"]
    return workspace_mgr.save_test_case(test_case, user["role"])


@router.get("/test-cases/{test_id}", response_model=TestCase)
def get_test_case(test_id: str, user: dict = Depends(get_current_user)):
    """Retrieves a single test case. Strictly denied for Blue Team."""
    return workspace_mgr.get_test_case(test_id, user["role"])
