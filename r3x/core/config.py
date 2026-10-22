"""
R3X Core Configuration & Settings Management
"""
import json
import os
from pathlib import Path

from pydantic import BaseModel, Field

DEFAULT_R3X_HOME = Path.home() / ".r3x"

# Ensure local project bin and ~/.local/bin are in system PATH for security tool discovery
_project_bin = Path(__file__).resolve().parent.parent.parent / "bin"
_user_local_bin = Path.home() / ".local" / "bin"
_current_path = os.environ.get("PATH", "")
_extra_paths = [str(_project_bin), str(_user_local_bin)]
for ep in _extra_paths:
    if ep not in _current_path:
        os.environ["PATH"] = f"{ep}:{os.environ.get('PATH', '')}"

class NetworkConfig(BaseModel):
    user_agent: str = "R3X-BugBounty-Security-Audit/1.0 (+https://github.com/r3xdec/r3x-bugbounty)"
    timeout_seconds: int = 15
    rate_limit_per_second: int = 5
    max_concurrent_tasks: int = 4
    verify_ssl: bool = True
    follow_redirects: bool = False  # Scope protection: don't blind redirect

class SafetyConfig(BaseModel):
    strict_scope_enforcement: bool = True
    allow_destructive_tests: bool = False  # Strictly forbidden
    require_confirmation_for_active: bool = True
    auto_redact_secrets: bool = True
    emergency_stop_triggered: bool = False

class Settings(BaseModel):
    version: str = "1.0.0"
    base_dir: Path = DEFAULT_R3X_HOME
    db_path: Path = DEFAULT_R3X_HOME / "r3x_memory.db"
    keystore_path: Path = DEFAULT_R3X_HOME / "vault.enc"
    audit_log_path: Path = DEFAULT_R3X_HOME / "audit.log"
    reports_dir: Path = DEFAULT_R3X_HOME / "reports"
    evidence_dir: Path = DEFAULT_R3X_HOME / "evidence"
    
    # Integrations default configs
    hermes_path: str | None = None
    hermes_endpoint: str = "http://127.0.0.1:8686"
    hexstrike_endpoint: str = "http://127.0.0.1:8888"
    webhook_url: str | None = None
    webhook_channel: str = "generic"
    
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)

    def ensure_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def load(cls, config_file: Path | None = None) -> "Settings":
        cfg_file = config_file or (DEFAULT_R3X_HOME / "config.json")
        if cfg_file.exists():
            try:
                with open(cfg_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return cls.model_validate(data)
            except Exception:
                instance = cls()
                return instance
        instance = cls()
        instance.ensure_directories()
        return instance

    def save(self, config_file: Path | None = None) -> None:
        cfg_file = config_file or (self.base_dir / "config.json")
        self.ensure_directories()
        with open(cfg_file, "w", encoding="utf-8") as f:
            f.write(self.model_dump_json(indent=2))

settings = Settings.load()
