from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class Role(str, Enum):
    OPERATOR = "operator"
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    REVIEWER = "reviewer"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OutcomeCategory(str, Enum):
    BLOCKED_BY_DEFENSE = "blocked_by_defense"
    MODEL_REFUSED = "model_refused"
    VULNERABILITY_EXPLOITED = "vulnerability_exploited"
    BENIGN_SUCCESS = "benign_success"
    TIMEOUT_EXCEEDED = "timeout_exceeded"
    EXECUTION_ERROR = "execution_error"


class TestCase(BaseModel):
    id: str
    name: str
    category: str  # prompt_injection, jailbreak, exfiltration, dos, benign
    severity: Severity = Severity.MEDIUM
    prompt: str
    expected_outcome: str = "blocked"
    tags: List[str] = Field(default_factory=list)
    created_at: str = ""
    author: str = "red_team"


class DefensiveRule(BaseModel):
    rule_id: str
    name: str
    rule_type: str  # regex_block, keyword_filter, token_cap, pii_scrubber
    pattern: str = ""
    action: str = "block"  # block, redact, alert
    description: str = ""


class DefensivePolicy(BaseModel):
    id: str
    name: str
    version: str = "1.0"
    is_active: bool = True
    description: str = ""
    rules: List[DefensiveRule] = Field(default_factory=list)
    updated_at: str = ""
    author: str = "blue_team"


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EvaluationConfig(BaseModel):
    name: str
    model_id: str = "mock-safety-llama-8b"
    policy_id: Optional[str] = None
    test_case_ids: List[str] = Field(default_factory=list)
    timeout_seconds: float = 5.0
    simulated_delay: float = 0.1
    trigger_timeout_test: bool = False  # intentionally test timeout limits


class TestResult(BaseModel):
    test_id: str
    test_name: str
    category: str
    severity: Severity
    prompt_hash: str  # SHA-256 of prompt to protect raw sensitive content from exports
    prompt_preview: str  # Redacted/truncated preview safe for general logs
    defense_triggered: Optional[str] = None
    model_response_snippet: str
    outcome: OutcomeCategory
    latency_ms: float
    passed_safety_gate: bool


class EvaluationRun(BaseModel):
    id: str
    name: str
    status: RunStatus = RunStatus.PENDING
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    operator_id: str
    model_id: str
    policy_id: Optional[str] = None
    test_set_version: str = "2026.10-v1.0"
    config_fingerprint: str = ""
    rerun_of_id: Optional[str] = None
    total_tests: int = 0
    completed_tests: int = 0
    passed_tests: int = 0  # Safe outcomes (blocked or safely refused)
    failed_tests: int = 0  # Unsafe outcomes (vulnerability exploited)
    timeout_tests: int = 0
    results: List[TestResult] = Field(default_factory=list)
    manifest_signature: Optional[str] = None
    start_event_hash: Optional[str] = None
    end_event_hash: Optional[str] = None
    model_weights_digest: str = "sha256-mock-llama-8b-weights-v1"
    runtime_environment: Dict[str, str] = Field(default_factory=dict)
    hardware_fingerprint: Dict[str, str] = Field(default_factory=dict)
    rng_seed: int = 42
    test_suite_merkle_root: str = ""


class AuditEvent(BaseModel):
    event_id: str
    timestamp: str
    actor: str
    role: Role
    run_id: Optional[str] = None
    event_type: str
    payload: Dict[str, Any]
    prev_hash: str
    event_hash: str


class AuditVerificationResult(BaseModel):
    is_valid: bool
    total_events: int
    first_event_timestamp: Optional[str] = None
    last_event_timestamp: Optional[str] = None
    broken_link_index: Optional[int] = None
    error_message: Optional[str] = None
    checked_hashes: List[Dict[str, Any]] = Field(default_factory=list)


class CheckpointAnchor(BaseModel):
    checkpoint_id: str
    timestamp: str
    block_height: int
    tip_hash: str
    merkle_root: str
    signer_key_fingerprint: str
    signature: str
    description: str = ""
    is_valid: Optional[bool] = True


class RunManifest(BaseModel):
    manifest_version: str = "1.0"
    run_id: str
    run_name: str
    model_id: str
    policy_id: Optional[str]
    test_set_version: str = "2026.10-v1.0"
    config_fingerprint: str = ""
    total_tests: int
    outcome_summary: Dict[str, int]
    test_fingerprints: List[str]
    started_at: str
    completed_at: str
    start_event_hash: str
    end_event_hash: str
    public_key_fingerprint: str
    signature: str
    model_weights_digest: str = "sha256-mock-llama-8b-weights-v1"
    runtime_environment: Dict[str, str] = Field(default_factory=dict)
    hardware_fingerprint: Dict[str, str] = Field(default_factory=dict)
    rng_seed: int = 42
    test_suite_merkle_root: str = ""


class SecurityBoundaryTestResult(BaseModel):
    test_id: str
    name: str
    description: str
    target_boundary: str  # red_to_blue, blue_to_red, tenant_to_model, audit_tamper, signature, canary
    action_attempted: str
    expected_result: str
    actual_result: str
    status: str  # PASSED (attack blocked), FAILED (boundary breached)
    evidence: str


# ================= Canary Secret Models =================
class CanaryToken(BaseModel):
    token_id: str
    name: str
    workspace_location: str  # red_team, blue_team, model
    description: str
    token_hash: str  # SHA-256 fingerprint; raw token is never exposed in logs
    file_name: str
    created_at: str
    tripped: bool = False
    trip_count: int = 0
    last_tripped_at: Optional[str] = None


class CanaryTripEvent(BaseModel):
    trip_id: str
    token_id: str
    token_name: str
    attempted_by_role: Role
    attempted_by_user: str
    target_workspace: str
    timestamp: str
    blocked: bool = True
    evidence: str


# ================= Repeatable Evaluation & Comparison Models =================
class RunComparisonItem(BaseModel):
    test_id: str
    test_name: str
    category: str
    baseline_outcome: str
    rerun_outcome: str
    outcomes_match: bool
    baseline_latency_ms: float
    rerun_latency_ms: float
    latency_delta_ms: float


class RunComparisonResult(BaseModel):
    baseline_run_id: str
    rerun_run_id: str
    model_id: str
    policy_id: Optional[str]
    test_set_version: str
    config_fingerprint_match: bool
    total_tests: int
    matched_outcomes: int
    divergent_outcomes: int
    reproducibility_percentage: float
    items: List[RunComparisonItem] = Field(default_factory=list)


# ================= Proof Mode & Evidence Report Models =================
class SecurityControlItem(BaseModel):
    control_id: str
    category: str  # "Tested Mechanism" or "Documented Assumption / Limitation"
    name: str
    description: str
    status: str  # "tested_passing", "tested_failing", "assumed_untested"
    is_tested: bool
    evidence_or_assumption: str


class ProofModeMatrix(BaseModel):
    total_controls: int
    tested_controls_count: int
    passing_tests_count: int
    failing_tests_count: int
    assumed_controls_count: int
    total_blocked_violations: int
    controls: List[SecurityControlItem] = Field(default_factory=list)


class EvidenceReport(BaseModel):
    report_id: str
    generated_at: str
    run_id: str
    run_name: str
    model_id: str
    policy_id: Optional[str]
    test_set_version: str
    config_fingerprint: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    timeout_tests: int
    outcomes_breakdown: Dict[str, int]
    audit_chain_valid: bool
    audit_events_count: int
    manifest_signature_valid: bool
    public_key_fingerprint: str
    blocked_violations_logged: int
    canaries_intact: bool
    canaries_tripped_count: int
    proof_mode_tested_passing: int
    proof_mode_assumed_limitations: int
    documented_limitations: List[str]
    export_disclaimer: str

