from r3x.scanners.request_importer import HTTPRequestImporter

SAMPLE_HTTP = """POST /api/v1/auth/login HTTP/1.1
Host: api.target.local
User-Agent: Mozilla/5.0
Content-Type: application/json
Authorization: Bearer mysecrettoken

{"user": "admin", "password": "password123"}
"""

def test_request_importer():
    parsed = HTTPRequestImporter.parse_raw_text(SAMPLE_HTTP)
    assert parsed["method"] == "POST"
    assert parsed["path"] == "/api/v1/auth/login"
    assert parsed["host"] == "api.target.local"
    assert parsed["headers"]["content-type"] == "application/json"
    assert "admin" in parsed["body"]
    assert parsed["full_url"] == "https://api.target.local/api/v1/auth/login"
