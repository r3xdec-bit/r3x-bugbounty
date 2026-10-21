"""
R3X Cross-Model Consensus Verification Engine
Validates critical security findings by comparing outputs of two independent AI models.
"""
import json
import re
from typing import Dict, Any, Tuple
from r3x.mixer.models import TaskRole
from r3x.mixer.router import model_router
from r3x.core.logger import logger
from r3x.memory.db import db

VERIFICATION_PROMPT = """
You are a Senior Principal Security Auditor and Vulnerability Verification Expert.
Review the following candidate security finding and empirical evidence:

TITLE: {title}
ENDPOINT: {endpoint}
SEVERITY: {severity}
EMPIRICAL EVIDENCE / HTTP TRACE:
{evidence}

Analyze carefully:
1. Is this an actual security vulnerability/misconfiguration, or an intended safe behavior / false positive?
2. What is your confidence score from 0.0 (certain false positive) to 1.0 (certain confirmed vulnerability)?
3. What is the verified severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)?
4. Brief technical justification.

Respond strictly in JSON format with keys:
{{
  "is_vulnerability": true/false,
  "confidence": 0.0 to 1.0,
  "verified_severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "reasoning": "string"
}}
"""

class DualModelVerifier:
    def __init__(self):
        pass

    def verify_finding(
        self,
        finding_id: str,
        title: str,
        endpoint: str,
        severity: str,
        evidence_snippet: str
    ) -> Dict[str, Any]:
        """
        Query two independent models and establish consensus.
        Returns consensus dictionary:
        {
            "final_status": "CONFIRMED" | "POTENTIAL" | "FALSE_POSITIVE",
            "confidence_score": float,
            "verified_severity": str,
            "consensus_notes": str
        }
        """
        logger.info(f"Running dual-model consensus verification on finding: {title}")

        prompt = VERIFICATION_PROMPT.format(
            title=title,
            endpoint=endpoint,
            severity=severity,
            evidence=evidence_snippet[:1500]
        )
        messages = [
            {"role": "system", "content": "You are an objective security evaluator. Output strict JSON only."},
            {"role": "user", "content": prompt}
        ]

        # Model A (Primary: e.g. NVIDIA or default router)
        res_a = model_router.generate(role=TaskRole.DEEP_REASONING, messages=messages, preferred_provider="nvidia")
        parsed_a = self._parse_json(res_a["content"])

        # Model B (Secondary: e.g. OpenRouter / OpenAI or fallback)
        res_b = model_router.generate(role=TaskRole.DEEP_REASONING, messages=messages, preferred_provider="openrouter")
        parsed_b = self._parse_json(res_b["content"])

        # Compare consensus
        is_vuln_a = parsed_a.get("is_vulnerability", True)
        is_vuln_b = parsed_b.get("is_vulnerability", True)
        conf_a = float(parsed_a.get("confidence", 0.75))
        conf_b = float(parsed_b.get("confidence", 0.75))

        avg_conf = round((conf_a + conf_b) / 2.0, 2)

        if is_vuln_a and is_vuln_b:
            if avg_conf >= 0.70:
                final_status = "CONFIRMED"
            else:
                final_status = "POTENTIAL"
        elif not is_vuln_a and not is_vuln_b:
            final_status = "FALSE_POSITIVE"
        else:
            final_status = "POTENTIAL"

        notes = (
            f"Dual-Model Audit Consensus: Model A ({res_a['provider']}: is_vuln={is_vuln_a}, conf={conf_a}), "
            f"Model B ({res_b['provider']}: is_vuln={is_vuln_b}, conf={conf_b}). "
            f"Summary A: {parsed_a.get('reasoning', '')[:100]}. "
            f"Summary B: {parsed_b.get('reasoning', '')[:100]}."
        )

        db.log_agent_action(
            scan_id=None,
            agent_name="FalsePositiveVerificationAgent",
            decision=f"Consensus: {final_status} (conf={avg_conf})",
            in_sum=f"Finding: {title} @ {endpoint}",
            out_sum=notes
        )

        return {
            "final_status": final_status,
            "confidence_score": avg_conf,
            "verified_severity": parsed_a.get("verified_severity", severity).upper(),
            "consensus_notes": notes
        }

    def _parse_json(self, text: str) -> Dict[str, Any]:
        try:
            # Look for JSON block in markdown or raw text
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                return json.loads(match.group(0))
        except Exception:
            pass
        return {"is_vulnerability": True, "confidence": 0.70, "verified_severity": "MEDIUM", "reasoning": text[:150]}

dual_verifier = DualModelVerifier()
