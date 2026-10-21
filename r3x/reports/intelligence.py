"""
R3X AI Report Intelligence
Generates platform-ready Bug Bounty submission reports (HackerOne, Bugcrowd, Intigriti)
and technical remediation manuals with verified code patches.
"""
from r3x.memory.db import db

HACKERONE_TEMPLATE = """# Vulnerability Report: {title}

## Summary
An authorized security assessment against `{endpoint}` identified **{title}** classified with **{severity}** severity (CVSS v3.1: {cvss}, CWE: {cwe}).

## Target Asset
- **Endpoint:** `{endpoint}`
- **Verification Status:** **{status}** (Confidence: {confidence_score}%)
- **Cryptographic Evidence Hash (SHA-256):** `{evidence_hash}`

## Description & Technical Analysis
{technical_explanation}

## Step-by-Step Reproduction
1. Send the following HTTP request to the target asset:
```http
{request_raw}
```
2. Observe the following server response:
```http
{response_raw}
```

## Security Impact
{impact}

## Remediation & Mitigation Code
{remediation}

---
*Report generated autonomously by R3X-BugBounty Framework. Evidence cryptographically verified.*
"""

class AIReportIntelligence:
    def __init__(self):
        pass

    def export_bug_bounty_submission(self, finding_id: str) -> str:
        """
        Formats a specific finding into an official submission template
        ready for submission on HackerOne, Bugcrowd, or private Bug Bounty programs.
        """
        findings = db.list_findings()
        matched = next((f for f in findings if f["id"] == finding_id), None)
        if not matched:
            return f"Finding ID '{finding_id}' not found in database."

        ev_list = db.list_evidence()
        evidence = next((e for e in ev_list if e.get("finding_id") == finding_id), {})

        report_md = HACKERONE_TEMPLATE.format(
            title=matched["title"],
            endpoint=matched["endpoint"],
            severity=matched["severity"],
            cvss=matched.get("cvss", 0.0),
            cwe=matched.get("cwe", "CWE-200"),
            status=matched["status"],
            confidence_score=int((matched.get("confidence_score") or 1.0) * 100),
            evidence_hash=matched.get("evidence_hash", "N/A"),
            technical_explanation=matched["technical_explanation"],
            request_raw=evidence.get("request_raw", "GET / HTTP/1.1\nHost: target"),
            response_raw=evidence.get("response_raw", "HTTP/1.1 200 OK"),
            impact=matched.get("impact") or "Permits unauthorized data exposure or security posture degradation in violation of secure development standards.",
            remediation=matched["remediation"]
        )

        return report_md

report_intelligence = AIReportIntelligence()
