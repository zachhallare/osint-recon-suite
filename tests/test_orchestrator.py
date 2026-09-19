import asyncio
import pytest
from unittest.mock import patch
from osint_recon.orchestrator import Orchestrator
from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, RiskLevel

class DelayMockModule(BaseModule):
    def __init__(self, name: str, delay: float, findings_count: int):
        self._name = name
        self.MODULE_NAME = name
        self.delay = delay
        self.findings_count = findings_count

    async def _run(self, target: str) -> list[Finding]:
        await asyncio.sleep(self.delay)
        return [
            Finding(
                module_name=self.MODULE_NAME,
                finding_type="mock",
                value=f"Finding {i} from {self.MODULE_NAME}",
                risk_level=RiskLevel.INFO,
            ) for i in range(self.findings_count)
        ]

@pytest.mark.anyio
async def test_orchestrator_concurrency(tmp_path):
    db_path = tmp_path / "test.db"
    
    # We create several mock modules that sleep for varying amounts of time
    modules = [
        DelayMockModule("mod_1", 0.1, 5),
        DelayMockModule("mod_2", 0.05, 10),
        DelayMockModule("mod_3", 0.2, 2),
        DelayMockModule("mod_4", 0.15, 3),
    ]
    
    orch = Orchestrator(modules=modules, db_path=db_path, confirm=False)
    
    # Run scan
    scan = await orch.run("example.com")
    
    # Verify all findings were generated
    assert len(scan.all_findings) == 20
    
    # All mock findings are RiskLevel.INFO, so score should be 0
    assert scan.total_risk_score == 0
    assert scan.overall_risk_tier == "Informational"
    
    # Verify all findings were persisted into the DB correctly without corruption
    saved_findings = orch.db.get_findings_for_run(scan.scan_run_id)
    assert len(saved_findings) == 20
    
    # Verify they came from all modules
    saved_modules = {row["module_name"] for row in saved_findings}
    assert saved_modules == {"mod_1", "mod_2", "mod_3", "mod_4"}

@pytest.mark.anyio
async def test_orchestrator_persistence_error_isolation(tmp_path):
    db_path = tmp_path / "test2.db"
    
    modules = [
        DelayMockModule("mod_ok1", 0.05, 2),
        DelayMockModule("mod_fail", 0.1, 3),
        DelayMockModule("mod_ok2", 0.15, 2),
    ]
    
    orch = Orchestrator(modules=modules, db_path=db_path, confirm=False)
    original_save = orch.db.save_findings
    
    def mock_save_findings(run_id, findings):
        if findings and findings[0].module_name == "mod_fail":
            raise RuntimeError("Simulated DB lock or disk error")
        return original_save(run_id, findings)
    
    with patch.object(orch.db, "save_findings", side_effect=mock_save_findings):
        scan = await orch.run("example.com")
        
    # Total findings generated in memory is 7 (all finished running)
    assert len(scan.all_findings) == 7
    
    # Check results statuses
    results_by_mod = {r.module_name: r for r in scan.results}
    from osint_recon.models import ModuleStatus, RiskLevel
    assert results_by_mod["mod_ok1"].status == ModuleStatus.SUCCESS
    assert results_by_mod["mod_ok2"].status == ModuleStatus.SUCCESS
    assert results_by_mod["mod_fail"].status == ModuleStatus.FAILED
    assert "Database persistence error" in results_by_mod["mod_fail"].error
    
    # DB should only have the 4 findings from the successful modules
    saved_findings = orch.db.get_findings_for_run(scan.scan_run_id)
    assert len(saved_findings) == 4
    
    saved_modules = {row["module_name"] for row in saved_findings}
    assert saved_modules == {"mod_ok1", "mod_ok2"}

@pytest.mark.anyio
async def test_orchestrator_diffing(tmp_path):
    db_path = tmp_path / "test_diff.db"
    
    class VaryingMockModule(BaseModule):
        def __init__(self, name: str):
            self.MODULE_NAME = name
            self.run_count = 1

        async def _run(self, target: str) -> list[Finding]:
            findings = []
            if self.run_count == 1:
                findings = [
                    Finding(module_name=self.MODULE_NAME, finding_type="mock", value="baseline", risk_level=RiskLevel.INFO),
                    Finding(module_name=self.MODULE_NAME, finding_type="mock", value="to_be_resolved", risk_level=RiskLevel.LOW),
                    Finding(module_name=self.MODULE_NAME, finding_type="mock", value="case_sensitive_path", risk_level=RiskLevel.INFO)
                ]
            elif self.run_count == 2:
                findings = [
                    Finding(module_name=self.MODULE_NAME, finding_type="mock", value="baseline", risk_level=RiskLevel.INFO),
                    Finding(module_name=self.MODULE_NAME, finding_type="mock", value="case_sensitive_path", risk_level=RiskLevel.INFO),
                    Finding(module_name=self.MODULE_NAME, finding_type="mock", value="CASE_SENSITIVE_PATH", risk_level=RiskLevel.INFO), # same string, different case
                    Finding(module_name=self.MODULE_NAME, finding_type="mock_new", value="new_finding", risk_level=RiskLevel.LOW)
                ]
            elif self.run_count == 3:
                findings = [
                    Finding(module_name=self.MODULE_NAME, finding_type="mock", value="baseline", risk_level=RiskLevel.INFO),
                    Finding(module_name=self.MODULE_NAME, finding_type="mock", value="case_sensitive_path", risk_level=RiskLevel.INFO),
                    Finding(module_name=self.MODULE_NAME, finding_type="mock", value="CASE_SENSITIVE_PATH", risk_level=RiskLevel.INFO),
                    Finding(module_name=self.MODULE_NAME, finding_type="mock_new", value="new_finding", risk_level=RiskLevel.LOW)
                ]
            self.run_count += 1
            return findings

    mod = VaryingMockModule("mod_diff")
    orch = Orchestrator(modules=[mod], db_path=db_path, confirm=False)
    
    # 1. First run (Baseline)
    scan1 = await orch.run("example.com")
    assert scan1.previous_scan_run_id is None
    assert len(scan1.new_findings) == 0
    assert len(scan1.resolved_findings) == 0
    
    # 2. Second run (Diff: 1 new, 1 resolved, 1 case-sensitive different finding)
    scan2 = await orch.run("example.com")
    assert scan2.previous_scan_run_id == scan1.scan_run_id
    
    # The casing change should NOT be merged. We should see CASE_SENSITIVE_PATH as a new finding.
    new_types = {f.finding_type: f.value for f in scan2.new_findings}
    assert len(scan2.new_findings) == 2
    assert new_types["mock_new"] == "new_finding"
    assert new_types["mock"] == "CASE_SENSITIVE_PATH"
    
    assert len(scan2.resolved_findings) == 1
    assert scan2.resolved_findings[0].value == "to_be_resolved"
    
    # 3. Third run (Nothing changed)
    scan3 = await orch.run("example.com")
    assert scan3.previous_scan_run_id == scan2.scan_run_id
    assert len(scan3.new_findings) == 0
    assert len(scan3.resolved_findings) == 0

@pytest.mark.anyio
async def test_orchestrator_module_failure_prevents_false_resolved(tmp_path):
    db_path = tmp_path / "test_module_failure.db"
    
    class UnstableModule(BaseModule):
        def __init__(self, name: str):
            self.MODULE_NAME = name
            self.run_count = 1

        async def _run(self, target: str) -> list[Finding]:
            if self.run_count == 2:
                self.run_count += 1
                raise Exception("Module crashed on second run")
            self.run_count += 1
            return [Finding(module_name=self.MODULE_NAME, finding_type="mock", value="previously_found", risk_level=RiskLevel.INFO)]

    mod = UnstableModule("mod_unstable")
    orch = Orchestrator(modules=[mod], db_path=db_path, confirm=False)
    
    # Run 1: Succeeds and saves a finding
    scan1 = await orch.run("example.com")
    assert len(scan1.all_findings) == 1
    
    # Run 2: Fails. Finding should NOT be listed as resolved.
    scan2 = await orch.run("example.com")
    assert scan2.results[0].status.value == "failed"
    assert len(scan2.resolved_findings) == 0

@pytest.mark.anyio
async def test_orchestrator_partial_scan_flag(tmp_path):
    db_path = tmp_path / "test_partial.db"
    
    class FlakyModule(BaseModule):
        def __init__(self, name: str):
            self.MODULE_NAME = name
            self.run_count = 1

        async def _run(self, target: str) -> list[Finding]:
            if self.run_count == 1:
                self.run_count += 1
                raise Exception("Network failure")
            return [Finding(module_name=self.MODULE_NAME, finding_type="mock", value="found", risk_level=RiskLevel.INFO)]

    class ReliableModule(BaseModule):
        MODULE_NAME = "mod_reliable"
        async def _run(self, target: str) -> list[Finding]:
            return [Finding(module_name=self.MODULE_NAME, finding_type="mock2", value="reliable", risk_level=RiskLevel.INFO)]
            
    orch = Orchestrator(modules=[FlakyModule("mod_flaky"), ReliableModule()], db_path=db_path, confirm=False)
    
    scan1 = await orch.run("example.com")
    assert scan1.previous_scan_run_id is None
    assert orch._overall_status(scan1) == "partial"
    
    scan2 = await orch.run("example.com")
    assert scan2.previous_scan_was_partial is True
    # The flaky module succeeded this time, yielding a new finding.
    assert len(scan2.new_findings) == 1

@pytest.mark.anyio
async def test_orchestrator_resolved_target_passed_to_modules(tmp_path):
    db_path = tmp_path / "test_target_passed.db"
    
    class TargetCheckingModule(BaseModule):
        def __init__(self):
            self.MODULE_NAME = "mod_target_checker"

        async def _run(self, target: str) -> list[Finding]:
            # Emit a finding with the target we were passed
            return [Finding(module_name=self.MODULE_NAME, finding_type="mock", value=target, risk_level=RiskLevel.INFO)]

    orch = Orchestrator(modules=[TargetCheckingModule()], db_path=db_path, confirm=False)
    
    scan = await orch.run("resolved.example.com", original_target="OriginalCorp")
    
    assert len(scan.all_findings) == 1
    # The finding value should be the resolved target, proving that's what the module received.
    assert scan.all_findings[0].value == "resolved.example.com"

@pytest.mark.anyio
async def test_orchestrator_module_subset_diffing(tmp_path):
    db_path = tmp_path / "test_module_subset.db"
    
    class ModA(BaseModule):
        MODULE_NAME = "mod_a"
        async def _run(self, target: str) -> list[Finding]:
            return [Finding(module_name=self.MODULE_NAME, finding_type="mock", value="a_finding")]

    class ModB(BaseModule):
        MODULE_NAME = "mod_b"
        async def _run(self, target: str) -> list[Finding]:
            return [Finding(module_name=self.MODULE_NAME, finding_type="mock", value="b_finding")]

    mod_a = ModA()
    mod_b = ModB()

    # Run 1: Both modules
    orch1 = Orchestrator(modules=[mod_a, mod_b], db_path=db_path, confirm=False)
    scan1 = await orch1.run("example.com")
    assert len(scan1.all_findings) == 2
    assert set(scan1.modules_run) == {"mod_a", "mod_b"}

    # Run 2: Only Mod A (Mod B is skipped)
    orch2 = Orchestrator(modules=[mod_a], db_path=db_path, confirm=False)
    scan2 = await orch2.run("example.com")
    assert len(scan2.all_findings) == 1
    assert set(scan2.modules_run) == {"mod_a"}
    assert set(scan2.previous_scan_modules) == {"mod_a", "mod_b"}
    # The finding from Mod B should NOT appear as resolved because Mod B didn't run
    assert len(scan2.resolved_findings) == 0

    # Run 3: Mod A and Mod B again
    orch3 = Orchestrator(modules=[mod_a, mod_b], db_path=db_path, confirm=False)
    scan3 = await orch3.run("example.com")
    assert len(scan3.all_findings) == 2
    assert set(scan3.modules_run) == {"mod_a", "mod_b"}
    assert set(scan3.previous_scan_modules) == {"mod_a"}
    # Mod B finding is "new" since it wasn't in Run 2 (which is the baseline for Run 3)
    assert len(scan3.new_findings) == 1
    assert scan3.new_findings[0].module_name == "mod_b"

