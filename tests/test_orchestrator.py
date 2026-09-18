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
    from osint_recon.models import ModuleStatus
    assert results_by_mod["mod_ok1"].status == ModuleStatus.SUCCESS
    assert results_by_mod["mod_ok2"].status == ModuleStatus.SUCCESS
    assert results_by_mod["mod_fail"].status == ModuleStatus.FAILED
    assert "Database persistence error" in results_by_mod["mod_fail"].error
    
    # DB should only have the 4 findings from the successful modules
    saved_findings = orch.db.get_findings_for_run(scan.scan_run_id)
    assert len(saved_findings) == 4
    
    saved_modules = {row["module_name"] for row in saved_findings}
    assert saved_modules == {"mod_ok1", "mod_ok2"}
