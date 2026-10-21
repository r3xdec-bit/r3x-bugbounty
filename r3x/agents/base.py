"""
R3X Base Agent Architecture
Standardized interface for all 11 autonomous agents.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from r3x.memory.db import db
from r3x.core.logger import logger

class BaseAgent(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def log_action(self, scan_id: Optional[str], decision: str, input_summary: str, output_summary: str) -> None:
        """Record structured decision log into memory database."""
        logger.info(f"[{self.name}] {decision}")
        db.log_agent_action(
            scan_id=scan_id,
            agent_name=self.name,
            decision_reason=decision,
            input_summary=input_summary,
            output_summary=output_summary
        )

    @abstractmethod
    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute agent workflow within provided context."""
        pass
