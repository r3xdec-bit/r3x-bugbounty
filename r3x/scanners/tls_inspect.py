"""
R3X TLS/SSL Inspection Scanner
Evaluates certificate validity, expiration dates, protocol versions, and cipher suites.
"""
import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from r3x.core.logger import logger
from r3x.scanners.base import BaseScanner
from r3x.security.scope_guardian import scope_guardian


class TLSInspector(BaseScanner):
    def scan(self, scan_id: str) -> list[dict[str, Any]]:
        findings = []
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname or self.target_url
        port = parsed.port or 443

        if parsed.scheme == "http" and port != 443:
            logger.info(f"TLSInspector: Target {self.target_url} is plain HTTP. Skipping TLS check.")
            return findings

        logger.info(f"TLSInspector: Inspecting TLS parameters on {hostname}:{port}")
        scope_guardian.throttle(max_rate_per_sec=5)

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Permissive to inspect untrusted certs too

            with (
                socket.create_connection((hostname, port), timeout=6.0) as sock,
                context.wrap_socket(sock, server_hostname=hostname) as ssock,
            ):
                cert = ssock.getpeercert(binary_form=False)
                version = ssock.version()
                cipher = ssock.cipher()

                raw_trace = f"TLS Protocol: {version}\nCipher Suite: {cipher}\nPeer Cert: {cert}"

                # 1. Check Deprecated Protocols (TLS 1.0 or 1.1)
                if version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    findings.append(self.record_finding(
                        scan_id=scan_id,
                        title=f"Deprecated TLS Protocol Version Supported ({version})",
                        severity="HIGH",
                        endpoint=f"{hostname}:{port}",
                        technical_explanation=f"Server negotiates connection using {version}. Older protocols suffer from structural cryptographic vulnerabilities (BEAST, POODLE) and fail compliance standards (PCI DSS).",
                        remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Enforce TLS 1.2 and TLS 1.3 exclusively.",
                        cwe="CWE-326",
                        cvss=7.5,
                        status="CONFIRMED",
                        response_raw=raw_trace
                    ))

                # 2. Check Expiration Date
                if cert and "notAfter" in cert:
                    # e.g. "May 15 12:00:00 2025 GMT"
                    not_after_str = cert["notAfter"]
                    try:
                        expire_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                        days_left = (expire_dt - datetime.now(UTC)).days
                        if days_left < 0:
                            findings.append(self.record_finding(
                                scan_id=scan_id,
                                title="Expired SSL/TLS Certificate",
                                severity="HIGH",
                                endpoint=f"{hostname}:{port}",
                                technical_explanation=f"The server's certificate expired on {not_after_str}. Web browsers will generate prominent security warnings.",
                                remediation="Renew and re-deploy a valid TLS certificate from an authorized CA.",
                                cwe="CWE-298",
                                cvss=6.5,
                                status="CONFIRMED",
                                response_raw=raw_trace
                            ))
                        elif days_left < 14:
                            findings.append(self.record_finding(
                                scan_id=scan_id,
                                title="SSL/TLS Certificate Expiring Soon (<14 Days)",
                                severity="LOW",
                                endpoint=f"{hostname}:{port}",
                                technical_explanation=f"Certificate expires in {days_left} days ({not_after_str}). Renewal needed promptly.",
                                remediation="Initiate certificate renewal procedure.",
                                cwe="CWE-298",
                                cvss=3.0,
                                status="CONFIRMED",
                                response_raw=raw_trace
                            ))
                    except Exception as e:
                        logger.debug(f"Certificate expiration parsing error: {e}")

        except Exception as e:
            logger.debug(f"TLSInspector connection error on {hostname}: {e}")

        return findings
