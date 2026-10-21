"""
R3X Passive Reconnaissance & DNS Intelligence Scanner
Gathers DNS records, nameservers, mail servers, and verifies domain health.
"""
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse

from r3x.scanners.base import BaseScanner
from r3x.security.scope_guardian import scope_guardian
from r3x.core.logger import logger

class PassiveReconScanner(BaseScanner):
    def scan(self, scan_id: str) -> List[Dict[str, Any]]:
        findings = []
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname or self.target_url

        logger.info(f"PassiveReconScanner: Conducting passive reconnaissance on {hostname}")
        scope_guardian.throttle(max_rate_per_sec=5)

        try:
            # 1. Resolve host IP addresses
            ip_addresses = socket.gethostbyname_ex(hostname)[2]
            raw_dns_info = f"Resolved IPs for {hostname}: {', '.join(ip_addresses)}"

            findings.append(self.record_finding(
                scan_id=scan_id,
                title="Passive DNS Enumeration & Host Mapping",
                severity="INFO",
                endpoint=hostname,
                technical_explanation=f"Domain {hostname} resolves to IP addresses: {', '.join(ip_addresses)}.",
                remediation="Ensure origin server IP addresses are masked behind a WAF / CDN proxy if cloud protection is desired.",
                cwe="CWE-200",
                cvss=0.0,
                status="CONFIRMED",
                response_raw=raw_dns_info
            ))

        except Exception as e:
            logger.debug(f"PassiveReconScanner DNS query error: {e}")

        return findings
