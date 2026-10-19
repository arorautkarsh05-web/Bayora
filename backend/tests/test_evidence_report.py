import asyncio
import pytest
from backend.app.models import EvaluationConfig, EvidenceReport
from backend.app.orchestrator import EvaluationOrchestrator


def test_evidence_report_generation_and_export():
    """Requirement 6: Evidence report contains run metadata, security checks, and limitations."""
    async def _test():
        orch = EvaluationOrchestrator()

        cfg = EvaluationConfig(
            name="Security Baseline Report Run",
            model_id="mock-safety-llama-8b",
            policy_id="policy-standard-shield",
            test_case_ids=["tc-001", "tc-002"],
        )

        run = orch.create_run(cfg, operator_id="operator-tester")
        await orch.execute_run(run.id, cfg)

        # 1. JSON Report
        report: EvidenceReport = orch.generate_evidence_report(run.id, format_type="json")
        assert report.run_id == run.id
        assert report.config_fingerprint != ""
        assert report.total_tests == 2
        assert report.audit_chain_valid is True
        assert report.manifest_signature_valid is True
        assert len(report.documented_limitations) >= 4

        # Residual risk disclosure check (Requirement 7)
        limitations_str = " ".join(report.documented_limitations)
        assert "ordinary container" in limitations_str.lower() or "shared" in limitations_str.lower()
        assert "side channel" in limitations_str.lower()
        assert "not guaranteed immutable" in limitations_str.lower() or "tamper-evident" in limitations_str.lower()

        # 2. Markdown Report
        md_report: str = orch.generate_evidence_report(run.id, format_type="markdown")
        assert isinstance(md_report, str)
        assert "# Bayora Security & Evaluation Evidence Report" in md_report
        assert report.config_fingerprint in md_report
        assert "Ed25519" in md_report
        assert "Residual Risks" in md_report

        # Strict check: NEVER leak raw credentials or passwords
        assert "secret_key" not in md_report.lower()
        assert "password" not in md_report.lower()
        assert "fake-canary-token" not in md_report.lower()

    asyncio.run(_test())

