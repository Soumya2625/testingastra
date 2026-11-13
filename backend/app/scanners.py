from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

from .rules import IAC_MATCHERS, IAC_RULES, SECRET_RULES
from .security import finding_fingerprint, masked_secret, redact_text

SCANNER_IMAGES = {
    "secrets": "zricethezav/gitleaks:v8.24.2",
    "iac": "bridgecrew/checkov:3.2.392",
    "sast": "semgrep/semgrep:1.101.0",
}
SCANNER_TIMEOUT_SECONDS = int(os.getenv("SCANNER_TIMEOUT_SECONDS", "600"))
MAX_FINDINGS = 5000

_IAC_DETAILS = {item[0]: item[1] for item in IAC_RULES}
_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
_SECRET_SEVERITY = {rule_id.removeprefix("secret."): severity for rule_id, _, severity in SECRET_RULES}
_SAST_RULE_MAP = {
    "astra-sql-injection": ("sast.sql_injection", "CWE-89"),
    "astra-sql-injection-taint": ("sast.sql_injection", "CWE-89"),
    "astra-command-injection": ("sast.command_injection", "CWE-78"),
    "astra-command-injection-taint": ("sast.command_injection", "CWE-78"),
    "astra-xss": ("sast.xss", "CWE-79"),
    "astra-path-traversal": ("sast.path_traversal", "CWE-22"),
    "astra-ssrf": ("sast.ssrf", "CWE-918"),
    "astra-insecure-deserialization": ("sast.insecure_deserialization", "CWE-502"),
    "astra-weak-crypto": ("sast.weak_crypto", "CWE-327"),
    "astra-insecure-auth": ("sast.insecure_authentication", "CWE-287"),
    "astra-missing-authorization": ("sast.missing_authorization", "CWE-862"),
    "astra-unsafe-file-operation": ("sast.unsafe_file_operation", "CWE-73"),
    "astra-dynamic-execution": ("sast.dynamic_execution", "CWE-95"),
}


def _line(value: Any) -> int | None:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return None


def _clean_path(value: Any) -> str:
    raw = str(value or "unknown").replace("\\", "/")
    parts = [part for part in raw.split("/") if part not in ("", ".", "..")]
    return "/".join(parts) or "unknown"


def _severity(value: Any, default: str = "medium") -> str:
    candidate = str(value or default).lower()
    return candidate if candidate in _SEVERITY else default


def normalize_secret(item: dict[str, Any]) -> dict[str, Any]:
    raw_rule_id = re.sub(r"[^a-z0-9]+", "_", str(item.get("RuleID", "unknown")).lower()).strip("_")
    rule_id = "secret." + raw_rule_id
    secret = str(item.get("Secret", ""))
    description = redact_text(str(item.get("Description") or item.get("RuleID") or "Secret detected"))
    path = _clean_path(item.get("File"))
    line = _line(item.get("StartLine"))
    return _finding(
        "secrets", rule_id, path, line, _SECRET_SEVERITY.get(raw_rule_id, _severity(item.get("Severity"), "high")),
        description, "Revoke and rotate the exposed credential, then remove it from source and history.",
        "confirmed", "high", evidence=masked_secret(secret), resource=None, cwe=None,
    )


def classify_iac(item: dict[str, Any]) -> str | None:
    check_id = str(item.get("check_id", "")).upper()
    known_check_ids = {
        "CKV_AWS_20": "public_storage", "CKV_AWS_53": "public_storage",
        "CKV_AWS_24": "open_ingress", "CKV_AWS_25": "open_ingress", "CKV_AWS_260": "open_ingress",
        "CKV_AWS_16": "missing_encryption", "CKV_AWS_19": "missing_encryption",
        "CKV_AWS_1": "permissive_iam", "CKV_AWS_41": "hardcoded_credentials",
        "CKV_K8S_20": "privileged_container", "CKV_K8S_22": "container_root",
        "CKV_K8S_10": "missing_resource_limits", "CKV_K8S_12": "missing_resource_limits",
        "CKV_K8S_13": "missing_resource_limits", "CKV_DOCKER_2": "insecure_dockerfile",
        "CKV_DOCKER_3": "insecure_dockerfile", "CKV_AWS_17": "public_database",
        "CKV_AWS_18": "logging_disabled",
    }
    if check_id in known_check_ids:
        return "iac." + known_check_ids[check_id]
    text = " ".join(
        str(item.get(field, "")) for field in ("check_name", "check_id", "resource", "guideline")
    ).lower()
    if ("database" in text or "rds" in text) and ("public" in text or "accessible" in text):
        return "iac.public_database"
    for key, terms in IAC_MATCHERS:
        if any(term in text for term in terms):
            return "iac." + key
    return None


def normalize_iac(item: dict[str, Any]) -> dict[str, Any] | None:
    rule_id = classify_iac(item)
    if not rule_id:
        return None
    ranges = item.get("file_line_range") or []
    line = _line(ranges[0]) if ranges else _line(item.get("line"))
    path = _clean_path(item.get("file_path"))
    check_name = redact_text(str(item.get("check_name") or _IAC_DETAILS[rule_id]))
    return _finding(
        "iac", rule_id, path, line, _severity(item.get("severity"), "medium"),
        check_name, redact_text(str(item.get("guideline") or "Apply the relevant security control and verify it in the target environment.")),
        "confirmed", "medium", evidence=None, resource=redact_text(str(item.get("resource") or ""))[:300] or None, cwe=None,
    )


def normalize_sast(item: dict[str, Any]) -> dict[str, Any]:
    extra = item.get("extra") or {}
    metadata = extra.get("metadata") or {}
    check_id = str(item.get("check_id", ""))
    normalized_check_id = check_id.rsplit(".", 1)[-1]
    mapped_rule, mapped_cwe = _SAST_RULE_MAP.get(normalized_check_id, (None, None))
    rule_id = mapped_rule or ("sast." + re.sub(r"[^a-z0-9_]+", "_", check_id.split(".")[-1].lower()))
    start = item.get("start") or {}
    end = item.get("end") or {}
    path = _clean_path(item.get("path"))
    line = _line(start.get("line"))
    cwe_value = metadata.get("cwe") or ([mapped_cwe] if mapped_cwe else None)
    cwe = cwe_value[0] if isinstance(cwe_value, list) and cwe_value else cwe_value
    return _finding(
        "sast", rule_id, path, line, _severity(
            {"error": "high", "warning": "medium", "info": "low"}.get(
                str(extra.get("severity", "")).lower(), extra.get("severity")), "medium"),
        redact_text(str(extra.get("message") or item.get("check_id") or "Static analysis finding")),
        redact_text(str(metadata.get("fix") or "Validate untrusted input and use the framework's safe API for this operation.")),
        "potential", "medium", evidence=None, resource=None, cwe=redact_text(str(cwe)) if cwe else None,
        end_line=_line(end.get("line")),
    )


def _finding(
    scanner: str, rule_id: str, path: str, line: int | None, severity: str, description: str,
    remediation: str, verification: str, confidence: str, evidence: str | None, resource: str | None,
    cwe: str | None, end_line: int | None = None,
) -> dict[str, Any]:
    return {
        "finding_id": finding_fingerprint(scanner, rule_id, path, line, resource or ""),
        "scanner": scanner, "rule_id": rule_id, "severity": severity, "cwe": cwe,
        "file_path": path, "line": line, "end_line": end_line, "resource": resource,
        "evidence": evidence, "description": description[:1000], "remediation": remediation[:2000],
        "confidence": confidence, "verification_status": verification, "status": "open",
    }


def _parse_json(stdout: str) -> Any:
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        for start in (stdout.find("{"), stdout.find("[")):
            if start >= 0:
                try:
                    return json.loads(stdout[start:])
                except json.JSONDecodeError:
                    continue
    raise RuntimeError("Scanner returned invalid JSON.")


def docker_command(scanner: str, source: Path, container_name: str | None = None) -> list[str]:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("Docker is unavailable. Install Docker Desktop with Linux containers enabled.")
    host_path = str(source.resolve())
    mount = f"type=bind,source={host_path},target=/src,readonly"
    common = [
        docker, "run", "--rm", "--name", container_name or f"astra-{scanner}-{uuid.uuid4().hex}",
        "--network", "none", "--memory", "1g", "--cpus", "1",
        "--pids-limit", "128", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "65532:65532", "--env", "HOME=/tmp",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--mount", mount, SCANNER_IMAGES[scanner],
    ]
    config_dir = Path(__file__).resolve().parent
    if scanner == "secrets":
        config_mount = f"type=bind,source={config_dir / 'gitleaks.toml'},target=/config/gitleaks.toml,readonly"
        return common[:-2] + ["--mount", config_mount] + common[-2:] + [
            "detect", "--source", "/src", "--no-git", "--config", "/config/gitleaks.toml",
            "--report-format", "json", "--report-path", "/dev/stdout",
        ]
    if scanner == "iac":
        return common + ["--directory", "/src", "--output", "json", "--quiet"]
    if scanner == "sast":
        config_mount = f"type=bind,source={config_dir / 'semgrep_rules.yml'},target=/config/semgrep.yml,readonly"
        return common[:-2] + ["--mount", config_mount] + common[-2:] + [
            "scan", "--config", "/config/semgrep.yml", "--json", "/src", "--no-git-ignore",
        ]
    raise ValueError(f"Unknown scanner: {scanner}")


async def _read_limited(stream: asyncio.StreamReader, limit: int) -> bytes:
    chunks = []
    size = 0
    while chunk := await stream.read(min(64 * 1024, limit + 1 - size)):
        size += len(chunk)
        if size > limit:
            raise RuntimeError("Scanner output exceeded its safe size limit.")
        chunks.append(chunk)
    return b"".join(chunks)


async def _collect_output(process: asyncio.subprocess.Process) -> tuple[bytes, bytes]:
    stdout_task = asyncio.create_task(_read_limited(process.stdout, 25 * 1024 * 1024))
    stderr_task = asyncio.create_task(_read_limited(process.stderr, 2 * 1024 * 1024))
    try:
        stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
        await process.wait()
        return stdout, stderr
    except BaseException:
        stdout_task.cancel()
        stderr_task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        raise


async def _kill_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    await process.wait()


async def _remove_container(docker: str, container_name: str) -> None:
    cleanup = await asyncio.create_subprocess_exec(
        docker, "rm", "--force", container_name,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        code = await asyncio.wait_for(cleanup.wait(), timeout=10)
    except asyncio.TimeoutError:
        await _kill_process(cleanup)
        raise RuntimeError("Docker did not confirm scanner-container cleanup.")
    if code not in (0, 1):
        raise RuntimeError("Docker could not clean up the cancelled scanner container.")


async def run_scanner(scanner: str, source: Path) -> list[dict[str, Any]]:
    container_name = f"astra-{scanner}-{uuid.uuid4().hex}"
    command = docker_command(scanner, source, container_name)
    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except OSError as error:
        raise RuntimeError(f"Could not start {scanner} scanner: {error}") from error
    try:
        stdout, _ = await asyncio.wait_for(_collect_output(process), timeout=SCANNER_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        await _kill_process(process)
        await _remove_container(command[0], container_name)
        raise RuntimeError(f"{scanner} scan exceeded the {SCANNER_TIMEOUT_SECONDS}-second timeout.")
    except asyncio.CancelledError:
        await _kill_process(process)
        await _remove_container(command[0], container_name)
        raise
    except RuntimeError as error:
        await _kill_process(process)
        await _remove_container(command[0], container_name)
        raise RuntimeError(f"{scanner} scan stopped: {error}") from error
    text = stdout.decode("utf-8", errors="replace")
    # Gitleaks and Semgrep use exit code 1 when findings are present.
    if process.returncode not in (0, 1):
        raise RuntimeError(f"{scanner} scanner failed (exit {process.returncode}).")
    try:
        raw = _parse_json(text)
    except RuntimeError as error:
        raise RuntimeError(f"{scanner} scanner failed to produce valid JSON: {str(error)}") from error
    if scanner == "secrets":
        results = [normalize_secret(entry) for entry in raw if isinstance(entry, dict)]
    elif scanner == "iac":
        groups = raw if isinstance(raw, list) else [raw]
        failed = [
            entry for group in groups if isinstance(group, dict)
            for entry in ((group.get("results") or {}).get("failed_checks", []))
        ]
        results = [finding for entry in failed if (finding := normalize_iac(entry))]
    else:
        results = [normalize_sast(entry) for entry in (raw.get("results") or []) if isinstance(entry, dict)]
    return results[:MAX_FINDINGS]
