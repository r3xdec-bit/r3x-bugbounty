"""
R3X Neural Brain
Central cognitive correlation engine that synthesizes multi-agent discoveries into cohesive attack graphs.
"""
from typing import Any

from r3x.core.logger import logger
from r3x.memory.db import db
from r3x.mixer.models import TaskRole
from r3x.mixer.router import model_router
from r3x.security.prompt_guard import sanitize_untrusted_prompt_data


class NeuralBrain:
    def __init__(self):
        pass

    def correlate_attack_surface(self, scan_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Synthesizes individual findings into actionable security correlations,
        identifying chained attack vectors (e.g., exposed docs + missing CORS + token leak).
        """
        logger.info(f"NeuralBrain: Correlating attack surface for scan {scan_id} ({len(findings)} findings)")

        titles = [f["finding"]["title"] for f in findings if "finding" in f]
        endpoints = [f["finding"]["endpoint"] for f in findings if "finding" in f]

        has_api = any("api" in t.lower() or "/api" in ep.lower() for t, ep in zip(titles, endpoints))
        has_cors = any("cors" in t.lower() for t in titles)
        has_token = any("secret" in t.lower() or "token" in t.lower() for t in titles)
        has_server_version = any("version disclosure" in t.lower() for t in titles)

        chains = []
        if has_cors and has_token:
            chains.append({
                "chain_id": "CHAIN-01",
                "name": "Cross-Origin Credential Harvest Vector",
                "severity": "CRITICAL",
                "description": "Permissive CORS policies coupled with client-side credential exposure permit automated cross-origin token harvesting."
            })

        if has_api and has_server_version:
            chains.append({
                "chain_id": "CHAIN-02",
                "name": "Targeted Component Exploitation Vector",
                "severity": "MEDIUM",
                "description": "Detailed software version disclosures combined with exposed API routes accelerate vulnerability targeting."
            })

        # Ask AI to synthesize high-level strategic posture
        evidence_summary = "\n".join([f"- {t} @ {ep}" for t, ep in zip(titles[:10], endpoints[:10])])
        prompt = f"""
You are the R3X Neural Brain. Analyze the following findings from an authorized security assessment:
{sanitize_untrusted_prompt_data(evidence_summary)}

Task:
1. Distinguish strictly between Verified Empirical Facts and Probabilistic Hypotheses.
2. Outline the top 2 prioritized remediation recommendations.
Keep response concise and direct.
"""
        synthesis_result = model_router.generate(
            role=TaskRole.DEEP_REASONING,
            messages=[{"role": "user", "content": prompt}]
        )

        analysis = {
            "scan_id": scan_id,
            "total_findings": len(findings),
            "attack_chains": chains,
            "empirical_facts_count": len(findings),
            "strategic_synthesis": synthesis_result["content"]
        }

        db.log_agent_action(
            scan_id=scan_id,
            agent_name="NeuralBrain",
            decision=f"Correlated {len(chains)} multi-vulnerability attack chains",
            input_summary=f"Findings evaluated: {len(findings)}",
            output_summary=f"Generated {len(chains)} chains, Strategic synthesis complete"
        )

        return analysis

neural_brain = NeuralBrain()
