"""
R3X AI Mixer Budget Guard
Enforces spending caps to prevent runaway API costs across all providers.
"""
from typing import Dict, Any, Optional
from r3x.core.exceptions import R3XError
from r3x.memory.db import db
from r3x.core.logger import logger

class BudgetExceededError(R3XError):
    """Raised when an operation would exceed the configured spending limit."""
    pass

class BudgetGuard:
    def __init__(self, max_cost_limit_usd: float = 10.0):
        self.max_cost_limit_usd = max_cost_limit_usd
        self._is_enforced: bool = True

    def set_budget(self, limit_usd: float) -> None:
        """Set maximum budget cap in USD."""
        self.max_cost_limit_usd = max(0.0, float(limit_usd))
        logger.info(f"BudgetGuard: Maximum spending cap set to ${self.max_cost_limit_usd:.2f} USD")

    def get_budget_status(self) -> Dict[str, Any]:
        """Check total current expenditure versus threshold."""
        usage = db.get_api_usage_summary()
        current_spent = usage.get("total_cost_usd", 0.0)
        remaining = max(0.0, self.max_cost_limit_usd - current_spent)
        pct_used = (current_spent / self.max_cost_limit_usd * 100.0) if self.max_cost_limit_usd > 0 else 100.0
        return {
            "max_budget_usd": self.max_cost_limit_usd,
            "total_spent_usd": current_spent,
            "remaining_usd": round(remaining, 4),
            "percentage_used": round(pct_used, 1),
            "is_exhausted": current_spent >= self.max_cost_limit_usd
        }

    def check_can_spend(self, estimated_next_cost: float = 0.001) -> None:
        """Verify before making an API call that spending limit has not been breached."""
        if not self._is_enforced:
            return
        status = self.get_budget_status()
        if (status["total_spent_usd"] + estimated_next_cost) > self.max_cost_limit_usd:
            raise BudgetExceededError(
                f"Budget Guard Alert: Total spending (${status['total_spent_usd']:.4f}) "
                f"would exceed maximum allowed budget cap of ${self.max_cost_limit_usd:.2f} USD. "
                "Adjust cap via 'r3x mixer budget --limit <USD>' or switch to local Ollama."
            )

budget_guard = BudgetGuard()
