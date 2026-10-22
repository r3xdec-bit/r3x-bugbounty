"""
R3X Dynamic Tool Manager & Consent-Based Installer
Enables discovery and safe execution of security and recon tools.
Never downloads or installs an external tool without explicit user authorization.
"""
import os
import shutil
import subprocess  # nosec B404
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from r3x.core.config import settings
from r3x.core.exceptions import R3XError
from r3x.core.logger import logger
from r3x.security.scope_guardian import scope_guardian

console = Console()

PROJECT_BIN_DIR = settings.base_dir / "bin"
USER_LOCAL_BIN = Path.home() / ".local" / "bin"

# Safe curated download recipes from verified official upstream releases
TOOL_RECIPES: dict[str, dict[str, str]] = {
    "nuclei": {
        "url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip",
        "archive_type": "zip",
        "binary_name": "nuclei",
        "description": "Fast and customizable vulnerability scanner based on simple YAML DSL."
    },
    "httpx": {
        "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip",
        "archive_type": "zip",
        "binary_name": "httpx",
        "description": "Fast and multi-purpose HTTP toolkit allowing multiple probes."
    },
    "subfinder": {
        "url": "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_linux_amd64.zip",
        "archive_type": "zip",
        "binary_name": "subfinder",
        "description": "Fast passive subdomain discovery tool."
    },
    "katana": {
        "url": "https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip",
        "archive_type": "zip",
        "binary_name": "katana",
        "description": "Next-generation crawling and spidering framework."
    },
    "dnsx": {
        "url": "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.2/dnsx_1.2.2_linux_amd64.zip",
        "archive_type": "zip",
        "binary_name": "dnsx",
        "description": "Fast and multi-purpose DNS toolkit allowing multiple DNS queries."
    },
    "amass": {
        "url": "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.tar.gz",
        "archive_type": "tar.gz",
        "binary_name": "amass",
        "description": "In-depth Attack Surface Mapping and Asset Discovery (OWASP)."
    },
    "ffuf": {
        "url": "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz",
        "archive_type": "tar.gz",
        "binary_name": "ffuf",
        "description": "Fast web fuzzer written in Go."
    }
}


class ToolManager:
    def __init__(self, bin_dir: Path | None = None):
        self.bin_dir = bin_dir or PROJECT_BIN_DIR
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        # Ensure our managed bin directory is in PATH
        current_path = os.environ.get("PATH", "")
        if str(self.bin_dir) not in current_path:
            os.environ["PATH"] = f"{self.bin_dir}:{current_path}"

    def is_installed(self, tool_name: str) -> bool:
        """Check whether a binary exists in PATH or local managed bin directory."""
        return shutil.which(tool_name) is not None

    def get_tool_path(self, tool_name: str) -> str | None:
        return shutil.which(tool_name)

    def request_installation_consent(
        self,
        tool_name: str,
        reason: str = "security assessment",
        interactive: bool = True
    ) -> bool:
        """
        Prompts user for explicit authorization prior to installing any third-party tool.
        """
        recipe = TOOL_RECIPES.get(tool_name.lower())
        desc = recipe.get("description", "Security tool") if recipe else "Security tool"

        console.print("\n[bold yellow]⚠️  Tool Requirement Notice[/]")
        console.print(f"Tool: [bold cyan]{tool_name}[/] - {desc}")
        console.print(f"Required for: [italic]{reason}[/]")

        if not interactive:
            logger.warning(f"ToolManager: Non-interactive mode, skipped installing '{tool_name}' without user consent.")
            return False

        try:
            approved = Confirm.ask(
                f"[bold green]Do you authorize downloading and installing '{tool_name}'?[/]",
                default=False
            )
            return approved
        except Exception:
            return False

    def install_tool(self, tool_name: str) -> bool:
        """
        Safely downloads and installs a verified tool from official releases into local user space.
        """
        name = tool_name.lower()
        if name not in TOOL_RECIPES:
            logger.error(f"ToolManager: No safe download recipe registered for '{tool_name}'.")
            return False

        recipe = TOOL_RECIPES[name]
        download_url = recipe["url"]
        binary_name = recipe["binary_name"]
        target_path = self.bin_dir / binary_name

        try:
            with tempfile.TemporaryDirectory() as tmp_work_dir:
                work_dir = Path(tmp_work_dir)
                tmp_archive = work_dir / f"{name}_archive"
                tmp_extract = work_dir / "extract"
                tmp_extract.mkdir(parents=True, exist_ok=True)

                logger.info(f"ToolManager: Downloading {name} from verified source...")
                console.print(f"[dim]Downloading {name} from {download_url}...[/]")
                urllib.request.urlretrieve(download_url, tmp_archive)  # nosec B310

                if recipe["archive_type"] == "zip":
                    with zipfile.ZipFile(tmp_archive, "r") as zf:
                        zf.extractall(tmp_extract)  # nosec B202
                elif recipe["archive_type"] == "tar.gz":
                    with tarfile.open(tmp_archive, "r:gz") as tf:
                        # Inspect members to ensure no path traversal
                        safe_members = []
                        for m in tf.getmembers():
                            target = (tmp_extract / m.name).resolve()
                            if tmp_extract.resolve() in target.parents or target == tmp_extract.resolve():
                                safe_members.append(m)
                        tf.extractall(tmp_extract, members=safe_members)  # nosec B202

                # Locate binary inside extracted files
                found = None
                for root, _, files in os.walk(tmp_extract):
                    if binary_name in files:
                        found = Path(root) / binary_name
                        break

                if found and found.exists():
                    shutil.copy2(found, target_path)
                    target_path.chmod(0o755)
                    # Link to user local bin as well if writable
                    try:
                        USER_LOCAL_BIN.mkdir(parents=True, exist_ok=True)
                        symlink_path = USER_LOCAL_BIN / binary_name
                        if symlink_path.exists() or symlink_path.is_symlink():
                            symlink_path.unlink()
                        symlink_path.symlink_to(target_path)
                    except Exception as e:
                        logger.debug(f"User bin symlink skipped: {e}")

                    logger.info(f"ToolManager: Successfully installed '{name}' to {target_path}")
                    console.print(f"[bold green]✓ Successfully installed '{name}'[/]")
                    return True
                else:
                    logger.error(f"ToolManager: Binary '{binary_name}' not found in downloaded archive.")
                    return False

        except Exception as e:
            logger.error(f"ToolManager: Failed to install '{name}': {e}")
            console.print(f"[bold red]✗ Installation failed: {e}[/]")
            return False

    def ensure_tool(
        self,
        tool_name: str,
        reason: str = "security assessment",
        interactive: bool = True
    ) -> bool:
        """
        Ensures a tool is ready for use; asks consent if missing.
        """
        if self.is_installed(tool_name):
            return True

        if self.request_installation_consent(tool_name, reason=reason, interactive=interactive):
            return self.install_tool(tool_name)

        return False

    def execute_safe(
        self,
        tool_name: str,
        args: list[str],
        target_url: str | None = None,
        timeout: int = 60
    ) -> subprocess.CompletedProcess:
        """
        Executes a security binary with Scope Guardian verification and strict timeout.
        """
        if target_url:
            scope_guardian.validate_target(target_url)

        tool_path = self.get_tool_path(tool_name)
        if not tool_path:
            raise R3XError(f"Tool '{tool_name}' is not installed or not in PATH.")

        cmd = [tool_path] + args
        logger.info(f"ToolManager: Executing {tool_name} with {len(args)} arguments")
        res = subprocess.run(  # nosec B603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return res


tool_manager = ToolManager()
