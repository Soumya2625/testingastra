# Astra Defense Security Scanner

A single-tenant security-scanning service with a dark web UI, asynchronous scans,
SQLite persistence, and Gemini-assisted explanations. Repository source is
downloaded as an archive and is never executed. Gitleaks, Checkov, and Semgrep run
in Docker containers with networking disabled, read-only source mounts, and
resource limits.

## Requirements

- Python 3.11+
- Docker Desktop with Linux containers enabled
- Node is not required
- Set `ASTRA_API_KEY` to a long random value before starting the API.
- Optionally set `GEMINI_API_KEY` and `GEMINI_MODEL` (defaults to
  `gemini-2.5-flash`). Gemini is never sent raw secret values.
- For local testing, copy `.env.example` to `.env` in the repository root and
  replace the placeholders. `.env` is loaded by the backend and is ignored by
  Git; never commit or share it.
- Optionally set `ASTRA_DB_PATH` (defaults to `backend/data/astra.sqlite3`) and
  `SCANNER_TIMEOUT_SECONDS` (defaults to 600).

The scanner images are version-pinned in `backend/app/scanners.py`. Pre-pull
them before running scans:

```powershell
docker pull zricethezav/gitleaks:v8.24.2
docker pull bridgecrew/checkov:3.2.392
docker pull semgrep/semgrep:1.101.0
```

Scanner containers have no network; source is mounted read-only and containers
run with memory, CPU, PID, and timeout limits.

## Run

```powershell
Copy-Item .env.example .env
# Edit .env locally and replace the example values with your own.
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. Enter the API key in the UI; it is held in memory
only. GitHub and GitLab repository tokens are also submitted only for the scan
request and are not persisted.

## Test

```powershell
cd backend
python -m unittest discover -s tests -v
```

The tests cover all configured rule categories, normalization, redaction, and
container isolation flags. End-to-end scans require Docker and the pinned
scanner images. Configure repository URL, branch, and selected scanners in the
UI, then select **Start Security Scan**.

## Limitations

- This repository was empty when implementation began; there is no existing
  Astra Defense authentication, repository integration, or Code Scanning module
  to reuse. The API key is a single-tenant access gate, not user-level identity
  or repository authorization.
- Only GitHub.com and GitLab.com HTTPS repository archives are supported.
- Scanner results are limited to what the pinned engines/rules detect; they do
  not establish that a repository is free of vulnerabilities.
- Scanner output remains available when Gemini is not configured. AI responses
  are advisory and never apply changes.
