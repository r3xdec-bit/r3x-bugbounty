"""
R3X Real-Time Terminal Agent Dashboard
Renders real-time live metrics and service telemetry inside the terminal.
"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from r3x.agents.registry import agent_registry
from r3x.cli.banner import get_live_status
from r3x.memory.db import db

console = Console()

def render_dashboard() -> None:
    """Render the full live operational dashboard with authentic metrics."""
    statuses = get_live_status()
    agents = agent_registry.list_all()
    scans = db.list_scans()
    usage = db.get_api_usage_summary()
    findings = db.list_findings()

    running_tasks = sum(1 for s in scans if s.get("status") == "RUNNING")
    completed_tasks = sum(1 for s in scans if s.get("status") == "COMPLETED")
    verified_findings = sum(1 for f in findings if f.get("status") == "CONFIRMED")
    total_tokens = usage.get("total_prompt_tokens", 0) + usage.get("total_completion_tokens", 0)
    total_cost = usage.get("total_cost_usd", 0.0)

    # 1. Services Table
    srv_table = Table(box=None, show_header=False, pad_edge=False)
    srv_table.add_column("Service", style="bold white", width=14)
    srv_table.add_column("Sep", style="bold cyan", width=2)
    srv_table.add_column("Status", width=40)

    for srv in ["Hermes", "HexStrike", "NVIDIA NIM", "AI Mixer"]:
        match_key = None
        for k in statuses:
            if k.lower() == srv.lower():
                match_key = k
                break

        if match_key:
            txt, color = statuses[match_key]
            # Format clean badge
            badge = "ACTIVE" if "ACTIVE" in txt or "READY" in txt or "CONFIGURED" in txt else ("CONNECTED" if "CONNECTED" in txt else "OFFLINE")
            badge_color = color
            srv_table.add_row(srv, ":", f"[{badge_color}][{badge}][/] [dim]({txt})[/]")
        else:
            srv_table.add_row(srv, ":", "[dim yellow][STANDBY][/]")

    # 2. Metrics Grid Table
    metrics_table = Table(box=None, show_header=False)
    metrics_table.add_column("Key", style="bold white", width=20)
    metrics_table.add_column("Value", style="bold cyan")

    metrics_table.add_row("Active Agents", f"[bold green]{len(agents)}[/]")
    metrics_table.add_row("Tasks Running", f"[bold yellow]{running_tasks}[/]")
    metrics_table.add_row("Tasks Completed", f"[bold green]{completed_tasks}[/]")
    metrics_table.add_row("API Cost", f"[bold green]${total_cost:.4f}[/]")
    metrics_table.add_row("Tokens Used", f"[bold cyan]{total_tokens:,}[/]")
    metrics_table.add_row("Verified Findings", f"[bold red]{verified_findings}[/]")

    # Compose into Panel
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(
        Panel(srv_table, title="[bold cyan]Integrations & Core Engines[/]"),
        Panel(metrics_table, title="[bold green]Live Operational Telemetry[/]")
    )

    console.print("\n[bold cyan]R3X-BugBounty V2 Real-Time Dashboard[/]\n")
    console.print(grid)
    console.print()
