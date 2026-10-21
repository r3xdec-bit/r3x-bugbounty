"""
R3X Self-Healing Framework
Detects tool & network failures, diagnoses root causes, suggests remediations, and safely retries.
Strictly prohibits autonomous execution of unverified shell commands.
"""
import shutil
import time
from collections.abc import Callable
from typing import Any

from r3x.core.logger import logger


class SelfHealingEngine:
    def __init__(self):
        pass

    def diagnose_failure(
        self,
        tool_name: str,
        error_message: str,
        target_endpoint: str | None = None
    ) -> dict[str, Any]:
        """
        Diagnoses root cause of tool failure and provides structured remediation guidance.
        """
        err_lower = error_message.lower()
        diagnosis = {
            "tool": tool_name,
            "root_cause": "UNKNOWN_ERROR",
            "is_recoverable": False,
            "suggested_action": "Inspect error logs for technical details.",
            "retry_delay_seconds": 0
        }

        # 1. WAF / Rate-Limiting Detection
        if "429" in err_lower or "rate limit" in err_lower or "too many requests" in err_lower:
            diagnosis["root_cause"] = "RATE_LIMIT_EXCEEDED"
            diagnosis["suggested_action"] = "Target server or API enforced rate limits. Throttling requests and applying exponential backoff."
            diagnosis["is_recoverable"] = True
            diagnosis["retry_delay_seconds"] = 5

        # 2. Connection Drops / Timeout
        elif "timeout" in err_lower or "timed out" in err_lower:
            diagnosis["root_cause"] = "NETWORK_TIMEOUT"
            diagnosis["suggested_action"] = "Network socket timeout. Suggest increasing timeout setting in config/default.yaml."
            diagnosis["is_recoverable"] = True
            diagnosis["retry_delay_seconds"] = 2

        # 3. Connection Refused / Service Down
        elif "connection refused" in err_lower or "connecterror" in err_lower:
            diagnosis["root_cause"] = "CONNECTION_REFUSED"
            diagnosis["suggested_action"] = f"Target host or daemon refused connection on {target_endpoint or 'endpoint'}. Verify service status."
            diagnosis["is_recoverable"] = False

        # 4. Missing Binary Diagnosis
        elif "not found" in err_lower or "no such file" in err_lower or ("executable" in err_lower) or not shutil.which(tool_name):
            diagnosis["root_cause"] = "MISSING_BINARY"
            diagnosis["suggested_action"] = f"Tool '{tool_name}' is not in system PATH. Run './install.sh' or install via package manager."
            diagnosis["is_recoverable"] = False

        logger.warning(f"SelfHealing: Diagnosed failure in '{tool_name}' -> Cause: {diagnosis['root_cause']}")
        return diagnosis

    def execute_with_self_healing(
        self,
        tool_name: str,
        action: Callable[[], Any],
        max_retries: int = 2
    ) -> Any:
        """
        Executes a task with safe diagnostic retry logic.
        Never executes arbitrary shell commands; only retries safe, typed callable actions.
        """
        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                return action()
            except Exception as e:
                last_error = e
                diag = self.diagnose_failure(tool_name, str(e))
                if diag["is_recoverable"] and attempt < max_retries:
                    delay = diag["retry_delay_seconds"]
                    logger.info(f"SelfHealing: Attempting recovery #{attempt} for '{tool_name}' in {delay}s...")
                    time.sleep(delay)
                    continue
                else:
                    break

        raise last_error

self_healing = SelfHealingEngine()
