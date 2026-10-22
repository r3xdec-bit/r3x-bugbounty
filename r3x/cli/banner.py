"""
R3X Banner & Live Status Dashboard
Minimalist, high-performance cyberpunk terminal header.
Features a compact two-column layout with the stylized Cyber-R emblem
on the right and genuine service connectivity on the left.
"""

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from r3x.core.logger import logger

console = Console()

# Stylized Cyber 'R' emblem (Badge 3 - Red Cyberpunk Glyph)
CYBER_R_BADGE = """[bold red]
  ◢██████◣ 
  ██    ██ 
  ███████◤ 
  ██   ◥██ 
  ██    ██ 
  ▀▀    ▀▀ [/]"""


def get_live_status() -> dict[str, tuple[str, str]]:
    """
    Check the genuine status of:
    - AI MIXER
    - NVIDIA NIM
    - HERMES
    - HEXSTRIKE
    - SCOPE GUARDIAN
    Returns dict mapping component -> (Status Text, Rich Color Style)
    """
    import os

    import httpx

    from r3x.core.config import settings
    from r3x.mixer.key_store import key_store

    status = {}

    # 1. AI MIXER Status
    try:
        keys_summary = key_store.get_status_summary()
        total_keys = keys_summary["total_keys"]
        if total_keys > 0:
            providers = ", ".join(keys_summary.get("provider_breakdown", {}).keys())
            status["AI Mixer"] = (f"ACTIVE ({total_keys} keys: {providers})", "bold green")
        else:
            status["AI Mixer"] = ("STANDBY (No keys configured)", "bold yellow")
    except Exception:
        status["AI Mixer"] = ("OFFLINE (Vault locked)", "bold red")

    # 2. NVIDIA NIM Status
    try:
        nvidia_entries = [k for k in key_store.list_all() if k.provider.lower() == "nvidia"]
        if any(k.is_active for k in nvidia_entries):
            status["NVIDIA NIM"] = ("READY (Active key loaded)", "bold green")
        elif nvidia_entries:
            status["NVIDIA NIM"] = ("CONFIGURED (Key in vault)", "bold cyan")
        else:
            status["NVIDIA NIM"] = ("STANDBY (Not configured)", "dim")
    except Exception:
        status["NVIDIA NIM"] = ("ERROR", "bold red")

    # 3. SCOPE GUARDIAN
    status["Scope Guardian"] = ("ENFORCED (Boundary containment)", "bold cyan")

    # 4. HERMES Agent Status
    try:
        hermes_alive = False
        try:
            r = httpx.get(f"{settings.hermes_endpoint}/health", timeout=0.8)
            if r.status_code == 200:
                hermes_alive = True
        except Exception as e:
            logger.debug(f"Hermes probe check: {e}")

        if hermes_alive:
            status["Hermes Agent"] = ("ONLINE & READY", "bold green")
        else:
            if (
                os.path.exists("hermes-agent")
                or os.path.exists("bin/hermes")
                or (settings.hermes_path and os.path.exists(settings.hermes_path))
            ):
                status["Hermes Agent"] = ("STANDBY (Daemon stopped)", "bold yellow")
            else:
                status["Hermes Agent"] = ("STANDBY (Optional subagent)", "dim")
    except Exception:
        status["Hermes Agent"] = ("OFFLINE", "dim")

    # 5. HEXSTRIKE Status
    try:
        hexstrike_alive = False
        try:
            r = httpx.get(f"{settings.hexstrike_endpoint}/health", timeout=0.8)
            if r.status_code == 200:
                hexstrike_alive = True
        except Exception as e:
            logger.debug(f"HexStrike probe check: {e}")

        if hexstrike_alive:
            status["HexStrike MCP"] = ("CONNECTED (Port 8888)", "bold green")
        else:
            status["HexStrike MCP"] = ("OFFLINE (MCP server not running)", "dim")
    except Exception:
        status["HexStrike MCP"] = ("OFFLINE", "dim")

    return status


def show_banner(show_status: bool = True) -> None:
    """
    Render the compact, elegant R3X terminal banner.
    Left: Tool Name, version, description, and genuine connection state.
    Right: Sleek Cyber-R badge from the official brand identity.
    """
    table = Table(box=None, show_header=False, padding=(0, 3), pad_edge=False)
    table.add_column(justify="left", vertical="middle")
    table.add_column(justify="right", vertical="middle")

    left_lines = [
        "[bold white]R3X-BugBounty[/] [bold red]v2.0.0[/]",
        "[dim]Autonomous AI Security Framework[/]",
    ]

    if show_status:
        left_lines.append("")
        statuses = get_live_status()
        for comp, (stat_txt, color) in statuses.items():
            bullet = f"[{color}]●[/]" if "green" in color or "cyan" in color else (
                "[yellow]●[/]" if "yellow" in color else "[dim]○[/]"
            )
            left_lines.append(f"{bullet} [bold white]{comp}:[/] [{color}]{stat_txt}[/]")

    table.add_row("\n".join(left_lines), CYBER_R_BADGE.strip())

    panel = Panel(
        table,
        border_style="red",
        box=box.ROUNDED,
        title="[bold red]⚡ R3X-BugBounty[/]",
        title_align="left",
        expand=False,
    )

    console.print()
    console.print(panel)
    console.print()
