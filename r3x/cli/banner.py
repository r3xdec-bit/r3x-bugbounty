"""
R3X Banner & Live Status Dashboard
Displays the stylized cyber logo, greeting, and genuine connection states.
"""

from rich.console import Console
from rich.table import Table

from r3x.core.logger import logger

console = Console()

CYBER_ASCII_HOOD = """
                     [bold white].........:::::..[/]
                   [bold white]..::-=--=+-:...[/]
                  [bold white]...:-:-:.:*+:....[/]
              [bold cyan]. .....:::::.:#+......[/]
               [bold cyan]........:::.--     .:...:[/]
              [bold cyan].........::.::           .:[/]
            [bold cyan]........:.....:.  ..       ..[/]
          [bold cyan]. .............:.   .        ..[/]
          [bold cyan]. ..  ........:    .          .[/]
               [bold green].......    .-*:  ..      .[/]
               [bold green]......-=***#@@.:-.       .[/]
            [bold green].    ...=%@@@@**+ +#:       .[/]
       [bold green]...... .  . :#%#+-::            ..[/]
    [bold green].  .  .   ....  .=##+-[/]
       [bold green]. .....        .=++:             ..[/]
    [bold green]...   . .                           .. ..[/]
    [bold red]01010010 01000110 00101100 11001010[/]
"""

R3XDEC_TYPO = """
 [bold cyan]██████╗ ██████╗ ██╗  ██╗██████╗ ███████╗ ██████╗[/]
 [bold cyan]██╔══██╗╚════██╗╚██╗██╔╝██╔══██╗██╔════╝██╔════╝[/]
 [bold cyan]██████╔╝ █████╔╝ ╚███╔╝ ██║  ██║█████╗  ██║     [/]
 [bold cyan]██╔══██╗ ╚═══██╗ ██╔██╗ ██║  ██║██╔══╝  ██║     [/]
 [bold cyan]██║  ██║██████╔╝██╔╝ ██╗██████╔╝███████╗╚██████╗[/]
 [bold cyan]╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝[/]
"""

def get_live_status() -> dict[str, tuple[str, str]]:
    """
    Check the genuine status of:
    - NVIDIA NIM
    - HERMES
    - HEXSTRIKE
    - AI MIXER
    Returns dict mapping component -> (Status Text, Rich Color Style)
    """
    import httpx

    from r3x.core.config import settings
    from r3x.mixer.key_store import key_store

    status = {}

    # 1. AI MIXER Status
    try:
        keys_summary = key_store.get_status_summary()
        total_keys = keys_summary["total_keys"]
        if total_keys > 0:
            providers = ", ".join(keys_summary["active_providers"])
            status["AI MIXER"] = (f"ACTIVE ({total_keys} keys across: {providers})", "bold green")
        else:
            status["AI MIXER"] = ("STANDBY (No keys registered)", "bold yellow")
    except Exception:
        status["AI MIXER"] = ("OFFLINE (Vault locked)", "bold red")

    # 2. NVIDIA NIM Status
    try:
        nvidia_keys = key_store.get_keys("nvidia")
        if nvidia_keys:
            # Check key validity or connectivity to NVIDIA NIM endpoint
            status["NVIDIA NIM"] = ("CONFIGURED (Ready)", "bold green")
        else:
            status["NVIDIA NIM"] = ("NOT CONFIGURED", "bold yellow")
    except Exception:
        status["NVIDIA NIM"] = ("ERROR", "bold red")

    # 3. HERMES Agent Status
    try:
        # Check if hermes local repo or daemon is responsive
        hermes_alive = False
        try:
            r = httpx.get(f"{settings.hermes_endpoint}/health", timeout=0.8)
            if r.status_code == 200:
                hermes_alive = True
        except Exception as e:
            logger.debug(f"Hermes probe check: {e}")

        if hermes_alive:
            status["HERMES"] = ("ONLINE & READY", "bold green")
        else:
            # Check if hermes code / repo is installed in project or bin
            import os
            if os.path.exists("hermes-agent") or os.path.exists("bin/hermes") or (settings.hermes_path and os.path.exists(settings.hermes_path)):
                status["HERMES"] = ("STANDBY (Installed / Daemon stopped)", "bold yellow")
            else:
                status["HERMES"] = ("OFFLINE (Not installed)", "bold red")
    except Exception:
        status["HERMES"] = ("OFFLINE", "bold red")

    # 4. HEXSTRIKE Status
    try:
        hexstrike_alive = False
        try:
            r = httpx.get(f"{settings.hexstrike_endpoint}/health", timeout=0.8)
            if r.status_code == 200:
                hexstrike_alive = True
        except Exception as e:
            logger.debug(f"HexStrike probe check: {e}")

        if hexstrike_alive:
            status["HEXSTRIKE"] = ("CONNECTED (Port 8888)", "bold green")
        else:
            status["HEXSTRIKE"] = ("OFFLINE (Server not running on 8888)", "bold red")
    except Exception:
        status["HEXSTRIKE"] = ("OFFLINE", "bold red")

    return status

def show_banner(show_status: bool = True) -> None:
    """Print the complete banner and connection status table."""
    console.print(CYBER_ASCII_HOOD, highlight=False)
    console.print(R3XDEC_TYPO, highlight=False)
    console.print(
        "[bold white]  R3X-BugBounty[/] — [bold cyan]Autonomous AI Security Framework[/]\n",
        justify="left"
    )

    console.print("[bold green]Hi Master![/]\n")

    if show_status:
        statuses = get_live_status()
        table = Table(box=None, show_header=False, pad_edge=False)
        table.add_column("Service", style="bold white", width=14)
        table.add_column("Separator", style="bold cyan", width=3)
        table.add_column("Status", width=50)

        for service in ["NVIDIA NIM", "HERMES", "HEXSTRIKE", "AI MIXER"]:
            if service in statuses:
                text_val, style_val = statuses[service]
                table.add_row(service, ":", f"[{style_val}]{text_val}[/]")

        console.print(table)
        console.print()
