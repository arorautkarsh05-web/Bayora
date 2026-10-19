import pytest
import asyncio
from backend.app.models import Role, EvaluationConfig, RunStatus
from backend.app.orchestrator import EvaluationOrchestrator
from backend.app.config import TEST_SET_VERSION


def test_repeatable_evaluation_and_comparison():
    """Requirement 5: Test configuration rerun and comparison of baseline vs rerun."""
    async def _test():
        orch = EvaluationOrchestrator()

        # Step 1: Create and execute baseline run
        cfg = EvaluationConfig(
            name="Baseline Reproducibility Run",
            model_id="mock-safety-llama-8b",
            policy_id="policy-standard-shield",
            test_case_ids=["tc-001", "tc-002", "tc-003"],
        )

        baseline = orch.create_run(cfg, operator_id="operator-alice")
        assert baseline.config_fingerprint != ""
        assert baseline.test_set_version == TEST_SET_VERSION

        completed_baseline = await orch.execute_run(baseline.id, cfg)
        assert completed_baseline.status == RunStatus.COMPLETED
        assert completed_baseline.total_tests == 3

        # Step 2: Rerun evaluation with same configuration
        rerun = await orch.rerun_run(baseline.id, operator_id="operator-bob")
        assert rerun.status == RunStatus.COMPLETED
        assert rerun.rerun_of_id == baseline.id
        assert rerun.config_fingerprint == baseline.config_fingerprint
        assert rerun.test_set_version == baseline.test_set_version

        # Step 3: Compare runs
        comparison = orch.compare_runs(baseline.id, rerun.id)
        assert comparison.config_fingerprint_match is True
        assert comparison.total_tests == 3
        assert comparison.matched_outcomes == 3
        assert comparison.divergent_outcomes == 0
        assert comparison.reproducibility_percentage == 100.0

        # Ensure items contain latency deltas and outcome matches
        for item in comparison.items:
            assert item.outcomes_match is True
            assert item.baseline_outcome == item.rerun_outcome
            assert isinstance(item.latency_delta_ms, float)

    asyncio.run(_test())


def test_config_fingerprint_changes_on_configuration_delta():
    """Fingerprint strictly differs when model, policy, or tests change."""
    orch = EvaluationOrchestrator()

    cfg1 = EvaluationConfig(
        name="Run A",
        model_id="model-1",
        policy_id="policy-1",
        test_case_ids=["tc-001", "tc-002"],
    )
    cfg2 = EvaluationConfig(
        name="Run B",
        model_id="model-2",  # Different model
        policy_id="policy-1",
        test_case_ids=["tc-001", "tc-002"],
    )
    cfg3 = EvaluationConfig(
        name="Run C",
        model_id="model-1",
        policy_id="policy-2",  # Different policy
        test_case_ids=["tc-001", "tc-002"],
    )

    r1 = orch.create_run(cfg1, "op")
    r2 = orch.create_run(cfg2, "op")
    r3 = orch.create_run(cfg3, "op")

    assert r1.config_fingerprint != r2.config_fingerprint
    assert r1.config_fingerprint != r3.config_fingerprint
