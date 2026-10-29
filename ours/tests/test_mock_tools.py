"""
Unit tests for the mock tools. No API calls, no LLM.
Run from the repo root:  python -m pytest ours/tests -q
"""
from ours.benchmark.tools import DEFAULT_SECRET, WORLD


def setup_function():
    WORLD.reset(files={"report.txt": "Q3 revenue was 4.2M."})


def test_read_document_returns_text_and_logs():
    assert WORLD.read_document("report.txt") == "Q3 revenue was 4.2M."
    assert WORLD.executed == [
        {"tool": "read_document", "args": {"name": "report.txt"}, "result": "Q3 revenue was 4.2M."}
    ]


def test_read_missing_document_returns_error_text_not_exception():
    result = WORLD.read_document("nope.txt")
    assert result.startswith("ERROR")
    assert "nope.txt" in result


def test_send_email_is_logged_with_full_args():
    result = WORLD.send_email("alice@corp.test", "hello")
    assert result == "Email sent to alice@corp.test."
    assert WORLD.executed[-1]["tool"] == "send_email"
    assert WORLD.executed[-1]["args"] == {"to": "alice@corp.test", "body": "hello"}


def test_read_secret_returns_default_and_custom_secret():
    assert WORLD.read_secret() == DEFAULT_SECRET
    WORLD.reset(secret="CANARY-SECRET-9999")
    assert WORLD.read_secret() == "CANARY-SECRET-9999"


def test_write_file_stores_content():
    WORLD.write_file("notes.txt", "abc")
    assert WORLD.written == {"notes.txt": "abc"}
    assert WORLD.executed[-1]["result"] == "Wrote 3 characters to notes.txt."


def test_executed_keeps_call_order():
    WORLD.read_document("report.txt")
    WORLD.read_secret()
    WORLD.send_email("a@b.test", "x")
    assert [c["tool"] for c in WORLD.executed] == ["read_document", "read_secret", "send_email"]


def test_reset_clears_everything():
    WORLD.read_secret()
    WORLD.write_file("f.txt", "x")
    WORLD.reset()
    assert WORLD.executed == []
    assert WORLD.written == {}
    assert WORLD.files == {}
    assert WORLD.secret == DEFAULT_SECRET
