from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from app import database
from app.main import ChatRequest, ScanRequest, chat, chat_history, run_scan


class ScanWorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_scanner_toggle_runs_independently_and_persists_status(self):
        previous_db = database.DB_PATH
        temp_dir = tempfile.TemporaryDirectory()
        database.DB_PATH = Path(temp_dir.name) / "workflow.sqlite3"
        database.initialize()
        calls: list[str] = []

        def fake_fetch(_repository, _branch, _token, destination):
            destination.mkdir(parents=True)
            (destination / "synthetic.txt").write_text("safe fixture")
            return 1, "b" * 40

        async def fake_scanner(scanner, _source):
            calls.append(scanner)
            await asyncio.sleep(0)
            return []

        try:
            for enabled_name in ("secrets", "iac", "sast"):
                scan_id = str(uuid.uuid4())
                tenant = "synthetic-tenant"
                database.execute(
                    "INSERT INTO scans(id,tenant,repository,branch,status,scanner_status,started_at) VALUES(?,?,?,?,?,?,?)",
                    (scan_id, tenant, "https://github.com/acme/example", "main", "queued", "{}", "2026-01-01T00:00:00Z"),
                )
                request = ScanRequest(
                    repository="https://github.com/acme/example",
                    branch="main",
                    scanners={name: name == enabled_name for name in ("secrets", "iac", "sast")},
                )
                with patch("app.main.fetch_repository", side_effect=fake_fetch), patch(
                    "app.main.run_scanner", side_effect=fake_scanner
                ):
                    await run_scan(scan_id, tenant, request, asyncio.Event())
                scan = database.row("SELECT status,scanner_status,scanned_files,commit_sha FROM scans WHERE id=?", (scan_id,))
                status = json.loads(scan["scanner_status"])
                self.assertEqual(scan["status"], "completed")
                self.assertEqual(scan["scanned_files"], 1)
                self.assertEqual(scan["commit_sha"], "b" * 40)
                self.assertEqual(status[enabled_name], "completed")
                self.assertEqual({name for name, value in status.items() if value == "skipped"},
                                 set(("secrets", "iac", "sast")) - {enabled_name})
            self.assertEqual(calls, ["secrets", "iac", "sast"])
        finally:
            database.DB_PATH = previous_db
            temp_dir.cleanup()

    async def test_chat_followups_persist_and_are_scoped_to_the_scan(self):
        previous_db = database.DB_PATH
        temp_dir = tempfile.TemporaryDirectory()
        database.DB_PATH = Path(temp_dir.name) / "chat.sqlite3"
        database.initialize()
        scan_id = str(uuid.uuid4())
        tenant = "synthetic-tenant"
        database.execute(
            "INSERT INTO scans(id,tenant,repository,branch,status,scanner_status,started_at) VALUES(?,?,?,?,?,?,?)",
            (scan_id, tenant, "https://github.com/acme/example", "main", "completed", "{}", "2026-01-01T00:00:00Z"),
        )
        try:
            with patch("app.main.generate_answer", side_effect=["First evidence-based answer.", "Follow-up answer."]):
                first = await chat(scan_id, ChatRequest(question="Summarize findings"), tenant)
                second = await chat(
                    scan_id,
                    ChatRequest(question="How should I fix it?", conversation_id=first["conversation_id"]),
                    tenant,
                )
            history = await chat_history(scan_id, first["conversation_id"], tenant)
            self.assertEqual(second["conversation_id"], first["conversation_id"])
            self.assertEqual(len(history["messages"]), 4)
            self.assertEqual(history["messages"][-1]["text"], "Follow-up answer.")
        finally:
            database.DB_PATH = previous_db
            temp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
