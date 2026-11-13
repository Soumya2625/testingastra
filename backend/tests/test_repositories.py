from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.repositories import RepositoryError, _repository_parts, fetch_repository, normalize_repository_url


class RepositoryValidationTests(unittest.TestCase):
    def test_only_trusted_https_hosts_without_embedded_credentials_are_accepted(self):
        self.assertEqual(_repository_parts("https://github.com/acme/app.git"), ("github", "acme/app"))
        self.assertEqual(
            normalize_repository_url("https://gitlab.com/group/subgroup/app/"),
            "https://gitlab.com/group/subgroup/app",
        )
        for repository in (
            "http://github.com/acme/app",
            "https://user:credential@github.com/acme/app",
            "https://github.com/acme/app?token=value",
            "https://github.attacker.example/acme/app",
        ):
            with self.subTest(repository=repository), self.assertRaises(RepositoryError):
                normalize_repository_url(repository)

    def test_archive_extraction_records_commit_and_rejects_traversal(self):
        def archive(entries: list[tuple[str, bytes]]) -> bytes:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                for name, data in entries:
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            return buffer.getvalue()

        class Response:
            def __init__(self, data: bytes, url: str):
                self.data = data
                self.url = url
                self.headers = {"Content-Length": str(len(data))}

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def geturl(self):
                return self.url

            def read(self, size=-1):
                return self.data if size < 0 else self.data[:size]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sha = "a" * 40
            responses = [
                Response(json.dumps({"sha": sha}).encode(), "https://api.github.com/repos/acme/app/commits/main"),
                Response(archive([("app-root/src/main.py", b"print('synthetic')")]),
                         "https://codeload.github.com/acme/app/tar.gz/main"),
            ]
            with patch("app.repositories.urllib.request.urlopen", side_effect=responses):
                count, actual_sha = fetch_repository("https://github.com/acme/app", "main", None, root / "safe")
            self.assertEqual(count, 1)
            self.assertEqual(actual_sha, sha)
            self.assertEqual((root / "safe" / "src" / "main.py").read_text(), "print('synthetic')")

            responses = [
                Response(json.dumps({"sha": sha}).encode(), "https://api.github.com/repos/acme/app/commits/main"),
                Response(archive([("app-root/../../outside.txt", b"synthetic")]),
                         "https://codeload.github.com/acme/app/tar.gz/main"),
            ]
            with patch("app.repositories.urllib.request.urlopen", side_effect=responses):
                with self.assertRaisesRegex(RepositoryError, "unsafe path"):
                    fetch_repository("https://github.com/acme/app", "main", None, root / "unsafe")
            self.assertFalse((root / "outside.txt").exists())

    def test_github_token_is_sent_only_as_an_authorization_header(self):
        archive_buffer = io.BytesIO()
        with tarfile.open(fileobj=archive_buffer, mode="w:gz"):
            pass

        class Response:
            def __init__(self, body, url):
                self.body = body
                self.url = url
                self.headers = {"Content-Length": str(len(body))}

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def geturl(self):
                return self.url

            def read(self, size=-1):
                return self.body

        calls = []
        sha = "c" * 40
        responses = [
            Response(json.dumps({"sha": sha}).encode(), "https://api.github.com/repos/acme/app/commits/main"),
            Response(archive_buffer.getvalue(), "https://codeload.github.com/acme/app/archive"),
        ]

        def fake_urlopen(request, timeout):
            calls.append(request)
            return responses.pop(0)

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("app.repositories.urllib.request.urlopen", side_effect=fake_urlopen):
                fetch_repository(
                    "https://github.com/acme/app", "main", "synthetic-repository-token", Path(temp_dir) / "src"
                )
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].get_header("Authorization"), "Bearer synthetic-repository-token")
        self.assertEqual(calls[1].get_header("Authorization"), "Bearer synthetic-repository-token")
        self.assertNotIn("synthetic-repository-token", calls[0].full_url)
        self.assertNotIn("synthetic-repository-token", calls[1].full_url)


if __name__ == "__main__":
    unittest.main()
