from __future__ import annotations

import io
import json
import re
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_EXTRACTED_BYTES = 300 * 1024 * 1024
MAX_FILES = 50_000
BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")


class RepositoryError(Exception):
    pass


def _repository_parts(repository: str) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(repository)
    try:
        has_port = parsed.port is not None
    except ValueError as error:
        raise RepositoryError("Repository URL is invalid.") from error
    if parsed.scheme != "https" or parsed.username or parsed.password or has_port or parsed.query or parsed.fragment:
        raise RepositoryError("Use an HTTPS GitHub.com or GitLab.com repository URL.")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if parsed.hostname == "github.com" and len(parts) == 2:
        owner, name = parts
        if any(part in {".", ".."} for part in (owner, name)) or not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise RepositoryError("Repository path contains unsupported characters.")
        return "github", f"{owner}/{name.removesuffix('.git')}"
    if parsed.hostname == "gitlab.com" and len(parts) >= 2:
        if any(part in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
            raise RepositoryError("Repository path contains unsupported characters.")
        return "gitlab", "/".join(parts).removesuffix(".git")
    raise RepositoryError("Only GitHub.com and GitLab.com repository URLs are supported.")


def normalize_repository_url(repository: str) -> str:
    provider, project = _repository_parts(repository)
    host = "github.com" if provider == "github" else "gitlab.com"
    return f"https://{host}/{project}"


def _headers(provider: str, token: str | None, archive: bool = False) -> dict[str, str]:
    headers = {"User-Agent": "AstraDefense-Scanner/1.0"}
    if archive and provider == "github":
        headers["Accept"] = "application/vnd.github+json"
    if token:
        if "\r" in token or "\n" in token:
            raise RepositoryError("Repository token format is invalid.")
        if provider == "gitlab":
            headers["PRIVATE-TOKEN"] = token
        else:
            headers["Authorization"] = "Bearer " + token
    return headers


def _download_url(provider: str, repo: str, revision: str) -> tuple[str, str]:
    encoded_revision = urllib.parse.quote(revision, safe="")
    if provider == "github":
        return f"https://api.github.com/repos/{repo}/tarball/{encoded_revision}", "api.github.com"
    project = urllib.parse.quote(repo, safe="")
    return (
        f"https://gitlab.com/api/v4/projects/{project}/repository/archive.tar.gz?sha={encoded_revision}",
        "gitlab.com",
    )


def _resolve_commit(provider: str, repo: str, branch: str, token: str | None) -> str:
    branch_ref = urllib.parse.quote(branch, safe="")
    if provider == "github":
        url = f"https://api.github.com/repos/{repo}/commits/{branch_ref}"
    else:
        project = urllib.parse.quote(repo, safe="")
        url = f"https://gitlab.com/api/v4/projects/{project}/repository/commits/{branch_ref}"
    request = urllib.request.Request(url, headers=_headers(provider, token))
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if urllib.parse.urlparse(response.geturl()).hostname not in {"api.github.com", "gitlab.com"}:
                raise RepositoryError("Repository revision redirected to an untrusted host.")
            data = response.read(64 * 1024)
        payload = json.loads(data)
        sha = payload.get("sha") or payload.get("id")
        if not isinstance(sha, str) or not re.fullmatch(r"[a-fA-F0-9]{40,64}", sha):
            raise RepositoryError("Repository provider returned an invalid commit identifier.")
        return sha
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise RepositoryError("Repository or branch was not found or is not accessible.") from error
        raise RepositoryError(f"Could not resolve repository revision (HTTP {error.code}).") from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise RepositoryError("Could not resolve repository revision. Check network connectivity and try again.") from error
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RepositoryError("Repository provider returned an invalid revision response.") from error


def fetch_repository(repository: str, branch: str, token: str | None, destination: Path) -> tuple[int, str]:
    if not BRANCH_RE.fullmatch(branch) or ".." in PurePosixPath(branch).parts:
        raise RepositoryError("Branch name is invalid.")
    provider, repo = _repository_parts(repository)
    commit_sha = _resolve_commit(provider, repo, branch, token)
    url, allowed_host = _download_url(provider, repo, commit_sha)
    request = urllib.request.Request(url, headers=_headers(provider, token, archive=True))
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            final_host = urllib.parse.urlparse(response.geturl()).hostname
            if final_host not in {allowed_host, "codeload.github.com"}:
                raise RepositoryError("Repository archive redirected to an untrusted host.")
            content_length = int(response.headers.get("Content-Length", "0") or 0)
            if content_length > MAX_ARCHIVE_BYTES:
                raise RepositoryError("Repository archive exceeds the 100 MB download limit.")
            data = response.read(MAX_ARCHIVE_BYTES + 1)
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            raise RepositoryError("Repository access was denied; check the selected branch and repository token.") from error
        if error.code == 404:
            raise RepositoryError("Repository or branch was not found or is not accessible.") from error
        raise RepositoryError(f"Repository provider returned HTTP {error.code}.") from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise RepositoryError("Could not retrieve the repository archive. Check network connectivity and try again.") from error
    if len(data) > MAX_ARCHIVE_BYTES:
        raise RepositoryError("Repository archive exceeds the 100 MB download limit.")

    extracted_size = 0
    file_count = 0
    root = destination.resolve()
    root.mkdir(parents=True, exist_ok=True)
    try:
        member_count = 0
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > 100_000:
                    raise RepositoryError("Repository archive contains too many entries.")
                pure = PurePosixPath(member.name)
                if pure.is_absolute() or "\\" in member.name or any(part in ("", ".", "..") for part in pure.parts):
                    raise RepositoryError("Repository archive contains an unsafe path.")
                relative = Path(*pure.parts[1:]) if len(pure.parts) > 1 else Path()
                target = (root / relative).resolve()
                if target != root and root not in target.parents:
                    raise RepositoryError("Repository archive contains an unsafe path.")
                if member.issym() or member.islnk() or member.isdev():
                    continue
                if member.isfile():
                    file_count += 1
                    extracted_size += member.size
                    if file_count > MAX_FILES or extracted_size > MAX_EXTRACTED_BYTES:
                        raise RepositoryError("Repository exceeds the safe file-count or extraction-size limit.")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        continue
                    with source, target.open("wb") as output:
                        output.write(source.read(member.size))
    except RepositoryError:
        raise
    except (tarfile.TarError, OSError) as error:
        raise RepositoryError("Repository archive could not be safely extracted.") from error
    return file_count, commit_sha
