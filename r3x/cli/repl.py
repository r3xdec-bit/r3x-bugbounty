"""
R3X Interactive Terminal Shell (REPL)
Provides auto-completion, command history, and direct execution within `r3x > `.
"""
import shlex

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from rich.console import Console

from r3x.cli.banner import show_banner

console = Console()

COMMANDS = [
    "setup",
    "doctor",
    "project new",
    "project list",
    "target add",
    "scope import",
    "scan --quick",
    "scan --full",
    "scan --api",
    "ai investigate",
    "mixer add",
    "mixer list",
    "mixer status",
    "mixer test",
    "agents",
    "evidence",
    "findings",
    "history",
    "resume",
    "diff",
    "report --html",
    "report --markdown",
    "report --json",
    "update",
    "help",
    "clear",
    "exit",
    "quit"
]

def run_repl(typer_app) -> None:
    """Run the interactive REPL loop."""
    show_banner(show_status=True)

    completer = WordCompleter(COMMANDS, ignore_case=True, sentence=True)
    history = InMemoryHistory()
    session = PromptSession(history=history, completer=completer)

    while True:
        try:
            user_input = session.prompt("r3x > ").strip()
            if not user_input:
                continue

            if user_input.lower() in ["exit", "quit", "q"]:
                console.print("[bold yellow]Exiting R3X-BugBounty. Farewell Master![/]")
                break

            if user_input.lower() == "clear":
                console.clear()
                show_banner(show_status=False)
                continue

            if user_input.lower() == "help":
                console.print("\n[bold cyan]Available Commands in R3X:[/]")
                for cmd in sorted(COMMANDS):
                    if cmd not in ["exit", "quit", "clear"]:
                        console.print(f"  [bold green]•[/] {cmd}")
                console.print()
                continue

            # Dispatch command through Typer
            args = shlex.split(user_input)
            try:
                typer_app(args, standalone_mode=False)
            except SystemExit:
                pass
            except Exception as e:
                console.print(f"[bold red]Error executing command:[/] {e}")

        except KeyboardInterrupt:
            console.print("\n[yellow](Use 'exit' or Ctrl+D to quit)[/]")
            continue
        except EOFError:
            console.print("\n[bold yellow]Session closed.[/]")
            break
