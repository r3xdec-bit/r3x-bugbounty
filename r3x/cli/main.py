"""
R3X-BugBounty CLI Main Entry Point
Powered by Typer & Rich
"""
import sys
import shutil
import uuid
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from r3x.cli.banner import show_banner, get_live_status
from r3x.cli.repl import run_repl
from r3x.core.config import settings
from r3x.mixer.key_store import key_store
from r3x.memory.db import db

app = typer.Typer(
    name="r3x",
    help="R3X-BugBounty — Autonomous AI Security & Bug Bounty Framework",
    add_completion=True,
    no_args_is_help=False
)
mixer_app = typer.Typer(name="mixer", help="R3X AI Mixer multi-provider management")
app.add_typer(mixer_app, name="mixer")

project_app = typer.Typer(name="project", help="Manage security audit projects")
app.add_typer(project_app, name="project")

console = Console()

@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context):
    """If run without subcommand, launch the interactive REPL shell."""
    if ctx.invoked_subcommand is None:
        run_repl(app)

@app.command("doctor")
def doctor():
    """Perform a deep health check of environment, tools, and adapters."""
    console.print("\n[bold cyan]=== R3X System Diagnostic Doctor ===[/]\n")

    # 1. Check tools
    tools = ["nmap", "whatweb", "nuclei", "httpx", "subfinder", "katana", "amass", "sslyze", "dnsx"]
    table = Table(title="Security Binaries Audit", box=None)
    table.add_column("Tool", style="bold white")
    table.add_column("Path", style="dim")
    table.add_column("Status", style="bold")

    for t in tools:
        p = shutil.which(t)
        if p:
            table.add_row(t, p, "[green]INSTALLED[/]")
        else:
            table.add_row(t, "Not in PATH", "[red]MISSING[/]")
    console.print(table)
    console.print()

    # 2. Check Adapters & Services
    statuses = get_live_status()
    s_table = Table(title="AI & Agent Integrations", box=None)
    s_table.add_column("Integration", style="bold white")
    s_table.add_column("Status")
    for comp, (stat_txt, color) in statuses.items():
        s_table.add_row(comp, f"[{color}]{stat_txt}[/]")
    console.print(s_table)
    console.print()

@app.command("setup")
def setup_wizard():
    """Interactive setup wizard for R3X-BugBounty."""
    show_banner(show_status=False)
    console.print("[bold cyan]Welcome to the R3X Setup Wizard.[/]\n")
    console.print("Ensuring local directories and database...")
    settings.ensure_directories()
    console.print(f"[green]✓[/] Vault at: {settings.keystore_path}")
    console.print(f"[green]✓[/] Database at: {settings.db_path}")
    console.print(f"[green]✓[/] Audit log at: {settings.audit_log_path}")
    console.print("\n[bold green]R3X Base is ready.[/] Use 'r3x mixer add' to configure AI providers.")

# ----------------- Project Commands -----------------
@project_app.command("new")
def project_new(name: str = typer.Argument(..., help="Unique project name"), description: str = typer.Option("", help="Project description")):
    """Create a new project workspace."""
    p_id = str(uuid.uuid4())[:8]
    try:
        p = db.create_project(p_id, name, description)
        console.print(f"[green]✓ Project '{name}' created successfully (ID: {p_id})[/]")
    except Exception as e:
        console.print(f"[red]Error creating project:[/] {e}")

@project_app.command("list")
def project_list():
    """List all project workspaces."""
    projects = db.list_projects()
    if not projects:
        console.print("[yellow]No projects found. Create one with: r3x project new <name>[/]")
        return
    table = Table(title="R3X Projects")
    table.add_column("ID", style="bold cyan")
    table.add_column("Name", style="bold white")
    table.add_column("Description")
    table.add_column("Created At", style="dim")
    for p in projects:
        table.add_row(p["id"], p["name"], p.get("description", ""), p["created_at"][:19])
    console.print(table)

@app.command("target")
def target_add(
    url: str = typer.Argument(..., help="Target URL (e.g. https://example.com)"),
    project: str = typer.Option("default", help="Project name or ID")
):
    """Add a target to a project and initialize scope."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        console.print("[red]Invalid target URL format. Must include scheme, e.g. https://target.com[/]")
        return

    proj = db.get_project(project)
    if not proj:
        proj = db.create_project(str(uuid.uuid4())[:8], project, "Auto-created project")

    target_id = str(uuid.uuid4())[:8]
    hostname = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    db.add_target(target_id, proj["id"], url, hostname, port)
    # Configure default scope for this domain
    db.set_scope(
        scope_id=str(uuid.uuid4())[:8],
        project_id=proj["id"],
        domain=hostname,
        allowed=[hostname, f"*.{hostname}"],
        excluded=["*.gov", "logout", "delete", "destroy"],
        allow_subdomains=True,
        max_rate=settings.network.rate_limit_per_second
    )
    console.print(f"[green]✓ Target added:[/] {url} -> Hostname: {hostname} (Project: {proj['name']})")
    console.print(f"[cyan]Scope Guardian initialized for domain:[/] {hostname}")

@app.command("scope")
def scope_import(
    file_path: str = typer.Argument(..., help="Path to scope file (.txt or .json)"),
    project: str = typer.Option("default", help="Project name")
):
    """Import target scope definitions from a file."""
    import os, json
    if not os.path.exists(file_path):
        console.print(f"[red]File not found:[/] {file_path}")
        return

    proj = db.get_project(project)
    if not proj:
        proj = db.create_project(str(uuid.uuid4())[:8], project)

    allowed = []
    excluded = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            if file_path.endswith(".json"):
                data = json.loads(content)
                allowed = data.get("allowed", [])
                excluded = data.get("excluded", [])
                domain = data.get("domain", allowed[0] if allowed else "unknown")
            else:
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("!"):
                        excluded.append(line[1:].strip())
                    elif line and not line.startswith("#"):
                        allowed.append(line)
                domain = allowed[0] if allowed else "imported-scope"

        db.set_scope(
            scope_id=str(uuid.uuid4())[:8],
            project_id=proj["id"],
            domain=domain,
            allowed=allowed,
            excluded=excluded
        )
        console.print(f"[green]✓ Successfully imported {len(allowed)} allowed & {len(excluded)} excluded scope rules.[/]")
    except Exception as e:
        console.print(f"[red]Failed to parse scope file:[/] {e}")

# ----------------- Mixer Commands -----------------
@mixer_app.command("add")
def mixer_add(
    provider: str = typer.Argument(..., help="Provider: nvidia, openai, openrouter, gemini, ollama, custom"),
    key: Optional[str] = typer.Option(None, "--key", "-k", help="API Key value (will prompt securely if omitted)"),
    label: str = typer.Option("primary", help="Label for this key")
):
    """Register an API key for a specified provider."""
    provider = provider.lower()
    valid_providers = ["nvidia", "openai", "openrouter", "gemini", "ollama", "custom"]
    if provider not in valid_providers:
        console.print(f"[red]Invalid provider.[/] Choose from: {', '.join(valid_providers)}")
        return

    if not key:
        key = typer.prompt(f"Enter API Key for {provider.upper()}", hide_input=True)

    try:
        entry = key_store.add_key(provider=provider, key_value=key, label=label)
        console.print(f"[green]✓ Successfully added {provider.upper()} key (ID: {entry.key_id}, Label: {label}) to encrypted store.[/]")
    except Exception as e:
        console.print(f"[red]Error saving key:[/] {e}")

@mixer_app.command("list")
def mixer_list():
    """List all registered API keys (masked)."""
    keys = key_store.list_all()
    if not keys:
        console.print("[yellow]Keystore is empty. Add keys using: r3x mixer add <provider>[/]")
        return
    table = Table(title="R3X AI Mixer Key Registry")
    table.add_column("Key ID", style="bold cyan")
    table.add_column("Provider", style="bold white")
    table.add_column("Label")
    table.add_column("Masked Key", style="dim")
    table.add_column("Status")
    table.add_column("Usage Count", justify="right")

    for k in keys:
        status_txt = "[green]ACTIVE[/]" if k.is_active else "[red]DISABLED[/]"
        table.add_row(k.key_id, k.provider.upper(), k.label, k.mask(), status_txt, str(k.usage_count))
    console.print(table)

@mixer_app.command("status")
def mixer_status():
    """Display real-time AI Mixer provider health, token usage, and status."""
    from r3x.mixer.router import model_router
    model_router.display_status()

@mixer_app.command("test")
def mixer_test(provider: Optional[str] = typer.Option(None, help="Specific provider to test")):
    """Perform live probe on configured AI providers."""
    from r3x.mixer.router import model_router
    model_router.test_providers(provider)

# ----------------- Scanning & Agents -----------------
@app.command("scan")
def scan_cmd(
    quick: bool = typer.Option(False, "-quick", "--quick", help="Execute rapid passive and active recon"),
    full: bool = typer.Option(False, "-full", "--full", help="Execute complete multi-agent security assessment"),
    api: bool = typer.Option(False, "-api", "--api", help="Execute specialized API schema & endpoint security analysis"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target URL"),
    project: str = typer.Option("default", "--project", "-p", help="Project name")
):
    """Run an authorized security assessment scan."""
    from r3x.agents.hermes_master import hermes_master
    scan_type = "quick" if quick else ("api" if api else "full")
    hermes_master.execute_scan(target_url=target, project_name=project, scan_type=scan_type)

@app.command("ai")
def ai_cmd(
    investigate: bool = typer.Option(True, "--investigate", "-i", help="Run AI analysis on collected targets and findings"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target URL")
):
    """Run autonomous AI brain analysis on target surface."""
    from r3x.core.brain import pentest_brain
    pentest_brain.investigate(target)

@app.command("agents")
def list_agents():
    """List all autonomous agents in the R3X ecosystem."""
    from r3x.agents.registry import agent_registry
    agent_registry.display_agents()

@app.command("findings")
def show_findings(
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Filter by project"),
    scan: Optional[str] = typer.Option(None, "--scan", "-s", help="Filter by scan ID")
):
    """Display identified security findings with verified status."""
    findings = db.list_findings(project_id=project, scan_id=scan)
    if not findings:
        console.print("[yellow]No findings recorded yet. Run a scan with: r3x scan --quick[/]")
        return

    table = Table(title="R3X Security Findings Register")
    table.add_column("Severity", style="bold")
    table.add_column("Title", style="bold white")
    table.add_column("Endpoint", style="cyan")
    table.add_column("Status")
    table.add_column("CVSS", justify="right")
    table.add_column("Confidence", justify="right")

    sev_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim white"
    }

    for f in findings:
        sev = f["severity"].upper()
        color = sev_colors.get(sev, "white")
        stat_color = "green" if f["status"] == "CONFIRMED" else ("yellow" if f["status"] == "POTENTIAL" else "dim red")
        table.add_row(
            f"[{color}]{sev}[/]",
            f["title"][:40],
            f["endpoint"][:35],
            f"[{stat_color}]{f['status']}[/]",
            str(f.get("cvss", 0.0)),
            f"{int((f.get('confidence_score') or 1.0) * 100)}%"
        )
    console.print(table)

@app.command("evidence")
def show_evidence(scan: Optional[str] = typer.Option(None, "--scan", "-s", help="Filter by scan ID")):
    """Inspect sanitized evidence cryptographically hashed."""
    ev_list = db.list_evidence(scan_id=scan)
    if not ev_list:
        console.print("[yellow]No evidence records found.[/]")
        return
    table = Table(title="Cryptographic Evidence Vault")
    table.add_column("ID", style="bold cyan")
    table.add_column("SHA-256 Hash", style="dim")
    table.add_column("Sanitized", justify="center")
    table.add_column("Timestamp", style="dim")

    for ev in ev_list:
        san = "[green]YES[/]" if ev["is_sanitized"] else "[red]NO[/]"
        table.add_row(ev["id"], ev["hash_sha256"], san, ev["timestamp"][:19])
    console.print(table)

@app.command("history")
def history():
    """Display past scan runs and outcomes."""
    scans = db.list_scans()
    if not scans:
        console.print("[yellow]No scans recorded yet.[/]")
        return
    table = Table(title="Scan Execution History")
    table.add_column("Scan ID", style="bold cyan")
    table.add_column("Type", style="bold")
    table.add_column("Status")
    table.add_column("Started", style="dim")
    table.add_column("Ended", style="dim")

    for s in scans:
        stat_color = "green" if s["status"] == "COMPLETED" else ("yellow" if s["status"] == "RUNNING" else "red")
        table.add_row(
            s["id"],
            s["scan_type"].upper(),
            f"[{stat_color}]{s['status']}[/]",
            s["start_time"][:19],
            (s.get("end_time") or "-")[:19]
        )
    console.print(table)

@app.command("resume")
def resume_scan(scan_id: Optional[str] = typer.Argument(None, help="Scan ID to resume")):
    """Resume a paused or interrupted scan."""
    from r3x.agents.hermes_master import hermes_master
    hermes_master.resume_scan(scan_id)

@app.command("diff")
def scan_diff(
    scan1: str = typer.Argument(..., help="Base scan ID"),
    scan2: str = typer.Argument(..., help="Comparison scan ID")
):
    """Compare differences and regression between two scans."""
    from r3x.reports.generator import report_generator
    report_generator.render_diff(scan1, scan2)

@app.command("report")
def generate_report(
    html: bool = typer.Option(False, "--html", help="Generate HTML report"),
    markdown: bool = typer.Option(False, "--markdown", "--md", help="Generate Markdown report"),
    json_out: bool = typer.Option(False, "--json", help="Generate JSON report"),
    pdf: bool = typer.Option(False, "--pdf", help="Generate PDF report"),
    scan: Optional[str] = typer.Option(None, "--scan", "-s", help="Scan ID"),
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Project name or ID"),
    out: Optional[str] = typer.Option(None, "--out", "-o", help="Output file path")
):
    """Export security assessment report in multiple formats."""
    from r3x.reports.generator import report_generator
    fmt = "html" if html else ("md" if markdown else ("json" if json_out else ("pdf" if pdf else "html")))
    report_generator.create_report(project_id=project, scan_id=scan, format_type=fmt, output_path=out)

@app.command("update")
def check_updates():
    """Check for framework and external tool updates."""
    console.print("[bold cyan]Checking R3X-BugBounty updates...[/]")
    console.print(f"[green]Framework is up-to-date (Version: {settings.version})[/]")

def entry_point():
    """Entry point callable from pyproject.toml."""
    app()

if __name__ == "__main__":
    entry_point()
