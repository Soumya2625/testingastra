from __future__ import annotations

SECRET_RULES = [
    ("secret.aws_access_key_id", "AWS access key ID", "high"),
    ("secret.aws_secret_access_key", "AWS secret access key", "critical"),
    ("secret.azure_client_secret", "Azure client secret", "high"),
    ("secret.azure_storage_key", "Azure storage account key", "high"),
    ("secret.gcp_service_account", "GCP service account credential", "critical"),
    ("secret.google_api_key", "Google API key", "high"),
    ("secret.github_token", "GitHub personal access token", "critical"),
    ("secret.gitlab_token", "GitLab access token", "critical"),
    ("secret.ssh_private_key", "Private SSH key", "critical"),
    ("secret.private_key", "RSA/EC private key", "critical"),
    ("secret.database_url", "Database connection string with credentials", "high"),
    ("secret.jwt_signing_secret", "JWT signing secret", "high"),
    ("secret.hardcoded_credential", "Hardcoded API token or password", "high"),
    ("secret.generic_high_entropy", "Generic high-entropy secret", "medium"),
]

IAC_RULES = [
    ("iac.public_storage", "Publicly exposed cloud storage"),
    ("iac.open_ingress", "Unrestricted inbound network access"),
    ("iac.missing_encryption", "Missing encryption configuration"),
    ("iac.permissive_iam", "Overly permissive IAM permissions"),
    ("iac.hardcoded_credentials", "Hardcoded credentials in infrastructure"),
    ("iac.privileged_container", "Privileged Kubernetes container"),
    ("iac.container_root", "Container running as root"),
    ("iac.missing_resource_limits", "Missing Kubernetes resource limits"),
    ("iac.insecure_dockerfile", "Insecure Dockerfile configuration"),
    ("iac.public_database", "Publicly exposed database"),
    ("iac.logging_disabled", "Security logging or monitoring disabled"),
]

SAST_RULES = [
    ("sast.sql_injection", "SQL injection", "CWE-89"),
    ("sast.command_injection", "Command injection", "CWE-78"),
    ("sast.xss", "Cross-site scripting", "CWE-79"),
    ("sast.path_traversal", "Path traversal", "CWE-22"),
    ("sast.ssrf", "Server-side request forgery", "CWE-918"),
    ("sast.insecure_deserialization", "Insecure deserialization", "CWE-502"),
    ("sast.weak_crypto", "Weak cryptographic algorithm", "CWE-327"),
    ("sast.insecure_authentication", "Insecure authentication implementation", "CWE-287"),
    ("sast.missing_authorization", "Missing authorization check", "CWE-862"),
    ("sast.unsafe_file_operation", "Unsafe file operation", "CWE-73"),
    ("sast.dynamic_execution", "Dangerous dynamic code execution", "CWE-95"),
]

ALL_RULE_IDS = {row[0] for row in SECRET_RULES + IAC_RULES + SAST_RULES}

IAC_MATCHERS = [
    ("public_storage", ("public access", "publicly accessible", "public_access_block", "public-read")),
    ("open_ingress", ("0.0.0.0/0", "unrestricted ingress", "open ingress")),
    ("missing_encryption", ("encryption", "encrypted", "kms", "storage encryption")),
    ("permissive_iam", ("wildcard", "administrative privileges", "full access", "iam policy")),
    ("hardcoded_credentials", ("password", "credential", "secret", "access key")),
    ("privileged_container", ("privileged",)),
    ("container_root", ("run as root", "runasnonroot", "run as non-root", "user instruction")),
    ("missing_resource_limits", ("resource limit", "cpu limit", "memory limit")),
    ("insecure_dockerfile", ("dockerfile", "latest tag", "healthcheck", "root user")),
    ("public_database", ("publicly accessible database", "database public", "public database")),
    ("logging_disabled", ("logging", "monitoring", "cloudtrail", "audit log")),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
