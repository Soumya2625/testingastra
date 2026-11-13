from __future__ import annotations

import hashlib
import re
from typing import Any

_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"(?i)(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"(?i)\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?i)\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"(?i)(?:AccountKey|azure_storage_key)\s*[:=]\s*['\"]?[A-Za-z0-9+/=]{32,}"),
    re.compile(r"(?i)(?:client_secret|azure_client_secret)\s*[:=]\s*['\"]?[A-Za-z0-9~._-]{20,}"),
    re.compile(r"(?i)(?:aws_secret_access_key|secret_access_key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{30,}"),
    re.compile(r"(?i)(?:jwt[_-]?(?:signing[_-]?)?secret|jwt[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*(['\"]?)[^\s,'\";]{8,}"),
    re.compile(r"(?i)(mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^:\s]+:[^@\s]+@"),
    re.compile(r"(?s)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]


def redact_text(value: str) -> str:
    result = value
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


def masked_secret(value: str) -> str:
    return "[REDACTED]"


def finding_fingerprint(scanner: str, rule_id: str, path: str, line: int | None, resource: str = "") -> str:
    material = "\0".join((scanner, rule_id, path.replace("\\", "/"), str(line or 0), resource))
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def sanitize_for_ai(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)[:4000]
    if isinstance(value, list):
        return [sanitize_for_ai(item) for item in value[:200]]
    if isinstance(value, dict):
        safe = {}
        for key, item in value.items():
            if key.lower() in {"secret", "secret_value", "raw_secret", "credential", "evidence"}:
                safe[key] = "[REDACTED]"
            else:
                safe[key] = sanitize_for_ai(item)
        return safe
    return value
