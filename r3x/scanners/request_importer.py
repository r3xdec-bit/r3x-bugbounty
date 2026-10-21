"""
R3X HTTP Request File Importer
Parses raw HTTP requests (.req, .http, Burp Suite export) for automated security assessment.
"""
import os
from typing import Any


class HTTPRequestImporter:
    @staticmethod
    def parse_raw_request_file(file_path: str, base_scheme: str = "https") -> dict[str, Any]:
        """
        Parse raw RFC 7230 HTTP request string from file.
        Returns dictionary:
        {
            "method": str,
            "path": str,
            "headers": Dict[str, str],
            "body": str,
            "host": str,
            "full_url": str
        }
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"HTTP request file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw_text = f.read()

        return HTTPRequestImporter.parse_raw_text(raw_text, base_scheme)

    @staticmethod
    def parse_raw_text(raw_text: str, base_scheme: str = "https") -> dict[str, Any]:
        lines = raw_text.splitlines()
        if not lines:
            raise ValueError("HTTP request file is empty")

        # First line: METHOD PATH HTTP/1.1
        request_line = lines[0].strip().split()
        if len(request_line) < 2:
            raise ValueError(f"Invalid HTTP request line: {lines[0]}")

        method = request_line[0].upper()
        path = request_line[1]

        headers: dict[str, str] = {}
        body_lines = []
        is_body = False

        for line in lines[1:]:
            if is_body:
                body_lines.append(line)
            else:
                if line.strip() == "":
                    is_body = True
                elif ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip().lower()] = val.strip()

        host = headers.get("host", "localhost")
        if path.startswith(("http://", "https://")):
            full_url = path
        else:
            full_url = f"{base_scheme}://{host}{path if path.startswith('/') else '/' + path}"

        body = "\n".join(body_lines)

        return {
            "method": method,
            "path": path,
            "host": host,
            "headers": headers,
            "body": body,
            "full_url": full_url
        }

request_importer = HTTPRequestImporter()
