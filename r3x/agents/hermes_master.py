"""
R3X Hermes Master Orchestrator
Coordinates multi-agent execution, adaptive task delegation, and lifecycle management.
"""
import uuid
from typing import Any

from rich.console import Console
from rich.panel import Panel

from r3x.agents.api_security_agent import api_security_agent
from r3x.agents.base import BaseAgent
from r3x.agents.cve_intel_agent import cve_intel_agent
from r3x.agents.evidence_collector_agent import evidence_collector_agent
from r3x.agents.js_analysis_agent import js_analysis_agent
from r3x.agents.recon_agent import recon_agent
from r3x.agents.scope_guardian_agent import scope_guardian_agent
from r3x.agents.verification_agent import verification_agent
from r3x.agents.web_security_agent import web_security_agent
from r3x.integrations.hermes_adapter import hermes_adapter
from r3x.memory.db import db

console = Console()

class HermesMasterOrchestrator(BaseAgent):
    def __init__(self):
        super().__init__(
            name="HermesMasterOrchestrator",
            description="Master AI agent for autonomous planning, task delegation, and cross-agent synthesis."
        )

    def execute_scan(self, target_url: str | None = None, project_name: str = "default", scan_type: str = "quick") -> dict[str, Any]:
        """
        Run the complete multi-agent authorized assessment pipeline.
        """
        # 1. Resolve project and target
        proj = db.get_project(project_name)
        if not proj:
            proj = db.create_project(str(uuid.uuid4())[:8], project_name, "Active workspace")

        if not target_url:
            targets = db.get_targets(proj["id"])
            if targets:
                target_url = targets[0]["url"]
            else:
                console.print("[red]No target specified. Use: r3x target add <url> or --target <url>[/]")
                return {}

        scan_id = str(uuid.uuid4())[:8]
        db.create_scan(scan_id=scan_id, project_id=proj["id"], scan_type=scan_type)

        console.print(Panel(
            f"[bold green]Starting R3X Security Assessment[/]\n"
            f"[bold white]Target:[/] {target_url}\n"
            f"[bold white]Project:[/] {proj['name']} (ID: {proj['id']})\n"
            f"[bold white]Scan ID:[/] {scan_id} (Mode: {scan_type.upper()})\n"
            f"[bold cyan]Orchestrated by Hermes Master AI[/]",
            title="[bold cyan]R3X-BugBounty Execution Pipeline[/]"
        ))

        context = {
            "target_url": target_url,
            "project_id": proj["id"],
            "scan_id": scan_id,
            "scan_type": scan_type,
            "findings": []
        }

        # -------------------------------------------------------------
        # Step 1: Scope Guardian Gate
        # -------------------------------------------------------------
        console.print("\n[bold cyan]Phase 1: Scope Guardian Authorization Check...[/]")
        try:
            scope_guardian_agent.run(context)
            console.print("  [bold green]✓[/] Scope verified. Target is strictly authorized.")
        except Exception as e:
            console.print(f"  [bold red]✗ SCOPE VIOLATION:[/] {e}")
            db.update_scan_status(scan_id, "FAILED", {"error": str(e)})
            return {}

        # -------------------------------------------------------------
        # Step 2: Hermes Planning & Task Delegation
        # -------------------------------------------------------------
        console.print("\n[bold cyan]Phase 2: Hermes AI Assessment Planning...[/]")
        scope_data = db.get_scope(proj["id"]) or {"target_domain": target_url}
        plan = hermes_adapter.create_security_plan(target_url, scope_data, scan_type=scan_type)
        console.print(f"  [bold green]✓[/] Hermes synthesized execution plan with {len(plan.get('stages', []))} stages.")

        # -------------------------------------------------------------
        # Step 3: Reconnaissance Agent
        # -------------------------------------------------------------
        console.print("\n[bold cyan]Phase 3: Dispatching ReconAgent (DNS & Fingerprinting)...[/]")
        recon_res = recon_agent.run(context)
        context["findings"].extend(recon_res.get("findings", []))
        console.print(f"  [bold green]✓[/] ReconAgent finished. Collected {len(recon_res.get('findings', []))} surface markers.")

        # -------------------------------------------------------------
        # Step 4: Web Security Baseline Audit
        # -------------------------------------------------------------
        console.print("\n[bold cyan]Phase 4: Dispatching WebSecurityAgent (Headers, CORS, Cookies, TLS)...[/]")
        web_res = web_security_agent.run(context)
        context["findings"].extend(web_res.get("findings", []))
        console.print(f"  [bold green]✓[/] WebSecurityAgent finished. Generated {len(web_res.get('findings', []))} baseline findings.")

        # -------------------------------------------------------------
        # Step 5: Dynamic AI Brain Decision - Specialized Agents
        # -------------------------------------------------------------
        console.print("\n[bold cyan]Phase 5: Hermes Brain Dynamic Surface Analysis...[/]")
        next_decisions = hermes_adapter.analyze_and_select_next_test(
            [f["finding"] for f in context["findings"]],
            target_url
        )
        console.print(f"  [bold yellow]• Hermes Decision:[/] {next_decisions['recommendation']}")

        if scan_type in ["full", "api"] or next_decisions.get("trigger_api_agent"):
            console.print("  Dispatching APISecurityAgent...")
            api_res = api_security_agent.run(context)
            context["findings"].extend(api_res.get("findings", []))

        if scan_type in ["full"] or next_decisions.get("trigger_js_agent"):
            console.print("  Dispatching JSAnalysisAgent...")
            js_res = js_analysis_agent.run(context)
            context["findings"].extend(js_res.get("findings", []))

        # Component CVE Intelligence
        console.print("  Dispatching CVEIntelligenceAgent...")
        cve_intel_agent.run(context)

        # -------------------------------------------------------------
        # Step 6: False Positive Verification (Dual-Model Consensus)
        # -------------------------------------------------------------
        console.print("\n[bold cyan]Phase 6: False Positive Verification Agent (Cross-Model Consensus)...[/]")
        verified_res = verification_agent.run(context)
        context["findings"] = verified_res.get("verified_findings", context["findings"])
        console.print("  [bold green]✓[/] Consensus verification completed on candidate findings.")

        # -------------------------------------------------------------
        # Step 7: Evidence Collection & Cryptographic Persistence
        # -------------------------------------------------------------
        console.print("\n[bold cyan]Phase 7: Evidence Collector Agent (Sanitizing & SHA-256 Hashing)...[/]")
        ev_res = evidence_collector_agent.run(context)
        console.print(f"  [bold green]✓[/] Successfully persisted {ev_res.get('saved_findings_count', 0)} findings to database.")

        # Update Scan Status in SQLite
        db.update_scan_status(
            scan_id,
            "COMPLETED",
            {"findings_count": len(context["findings"]), "target": target_url}
        )

        console.print("\n[bold green]✓ Scan Completed Successfully![/] Run 'r3x findings' or 'r3x report --html' to view results.\n")
        return context

    def resume_scan(self, scan_id: str | None = None) -> None:
        """Resume a paused or interrupted scan."""
        if not scan_id:
            scans = db.list_scans()
            if not scans:
                console.print("[yellow]No scans found to resume.[/]")
                return
            scan_id = scans[0]["id"]

        scan = db.get_scan(scan_id)
        if not scan:
            console.print(f"[red]Scan ID {scan_id} not found.[/]")
            return

        console.print(f"[bold cyan]Resuming scan {scan_id} (Type: {scan['scan_type']})...[/]")
        proj = db.get_project(scan["project_id"])
        targets = db.get_targets(proj["id"])
        target_url = targets[0]["url"] if targets else "https://target.local"
        self.execute_scan(target_url=target_url, project_name=proj["name"], scan_type=scan["scan_type"])

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        return self.execute_scan(
            target_url=context.get("target_url"),
            project_name=context.get("project_name", "default"),
            scan_type=context.get("scan_type", "quick")
        )

hermes_master = HermesMasterOrchestrator()
