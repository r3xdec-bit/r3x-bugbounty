"""
R3X Agent Registry & Ecosystem Manager
Registers and monitors all 11 autonomous security agents.
"""
from typing import Any

from rich.console import Console
from rich.table import Table

from r3x.agents.ai_mixer_agent import ai_mixer_agent
from r3x.agents.api_security_agent import api_security_agent
from r3x.agents.auth_differential_agent import auth_differential_agent
from r3x.agents.cve_intel_agent import cve_intel_agent
from r3x.agents.evidence_collector_agent import evidence_collector_agent
from r3x.agents.js_analysis_agent import js_analysis_agent
from r3x.agents.recon_agent import recon_agent
from r3x.agents.report_generator_agent import report_generator_agent
from r3x.agents.scope_guardian_agent import scope_guardian_agent
from r3x.agents.verification_agent import verification_agent
from r3x.agents.web_security_agent import web_security_agent

console = Console()

class AgentRegistry:
    def __init__(self):
        self._agents: dict[str, Any] = {
            "ScopeGuardianAgent": scope_guardian_agent,
            "ReconAgent": recon_agent,
            "WebSecurityAgent": web_security_agent,
            "APISecurityAgent": api_security_agent,
            "JSAnalysisAgent": js_analysis_agent,
            "AuthDifferentialAgent": auth_differential_agent,
            "CVEIntelligenceAgent": cve_intel_agent,
            "EvidenceCollectorAgent": evidence_collector_agent,
            "FalsePositiveVerificationAgent": verification_agent,
            "ReportGeneratorAgent": report_generator_agent,
            "AIMixerAgent": ai_mixer_agent,
        }

    def get_agent(self, name: str) -> Any:
        return self._agents.get(name)

    def list_all(self) -> list[dict[str, str]]:
        agents_list = [
            {"name": "HermesMasterOrchestrator", "role": "Master Orchestration, Planning, and Multi-Agent Coordination", "status": "ACTIVE"},
        ]
        for name, agent in self._agents.items():
            agents_list.append({
                "name": name,
                "role": agent.description,
                "status": "READY"
            })
        return agents_list

    def display_agents(self) -> None:
        table = Table(title="R3X Autonomous Multi-Agent System (12 Agents)", box=None)
        table.add_column("#", justify="right", style="dim", width=4)
        table.add_column("Agent Name", style="bold cyan", no_wrap=True)
        table.add_column("Role & Capabilities", style="white")
        table.add_column("Status", width=10)

        for i, a in enumerate(self.list_all(), 1):
            table.add_row(str(i), a["name"], a["role"], f"[green]{a['status']}[/]")

        console.print(table)
        console.print()

agent_registry = AgentRegistry()
