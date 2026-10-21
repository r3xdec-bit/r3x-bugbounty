"""
R3X Cryptographic Hashing Utilities
"""
import hashlib


def compute_sha256(data: str) -> str:
    """Calculate SHA-256 hexadecimal digest for raw content."""
    if not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
