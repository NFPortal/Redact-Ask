import io

import pytest

from redactask import input_reader
from redactask.models import InputError, UsageError


class FakeStdin(io.StringIO):
    def __init__(self, text="", tty=False):
        super().__init__(text)
        self._tty = tty

    def isatty(self):
        return self._tty


def test_file_and_question(tmp_path):
    f = tmp_path / "a.log"
    f.write_bytes(b"line1\r\nline2\r\n")
    r = input_reader.read("why?", str(f), None, 5000, 1_000_000, stdin=FakeStdin(tty=True))
    assert r.text == "line1\nline2" + input_reader.QUESTION_MARKER + "why?"
    assert r.text[r.question_offset:] == "why?"
    assert r.source == "file:a.log"


def test_piped_stdin():
    r = input_reader.read("q", None, None, 5000, 1_000_000, stdin=FakeStdin("hello\n"))
    assert r.text.startswith("hello") and r.source == "stdin"


def test_question_only_when_pipe_empty():
    r = input_reader.read("just a question", None, None, 5000, 1_000_000, stdin=FakeStdin(""))
    assert r.source == "none" and r.text.endswith("just a question")


def test_limits(tmp_path):
    f = tmp_path / "big.log"
    f.write_text("x\n" * 11)
    with pytest.raises(InputError, match="lines"):
        input_reader.read("q", str(f), None, 10, 1_000_000, stdin=FakeStdin(tty=True))
    with pytest.raises(InputError, match="bytes"):
        input_reader.read("q", str(f), None, 5000, 5, stdin=FakeStdin(tty=True))


def test_binary_and_empty(tmp_path):
    b = tmp_path / "bin"
    b.write_bytes(b"abc\x00def")
    with pytest.raises(InputError, match="binary"):
        input_reader.read("q", str(b), None, 5000, 1_000_000, stdin=FakeStdin(tty=True))
    e = tmp_path / "empty"
    e.write_text("  \n")
    with pytest.raises(InputError, match="empty"):
        input_reader.read("q", str(e), None, 5000, 1_000_000, stdin=FakeStdin(tty=True))


def test_invalid_utf8_replaced(tmp_path):
    f = tmp_path / "latin.log"
    f.write_bytes(b"caf\xe9 ok")
    r = input_reader.read("q", str(f), None, 5000, 1_000_000, stdin=FakeStdin(tty=True))
    assert "\ufffd" in r.text and r.warnings


def test_text_argument_is_the_default_source():
    r = input_reader.read("q", None, "pasted\r\nlog line", 5000, 1_000_000, stdin=FakeStdin(tty=True))
    assert r.source == "text" and r.text.startswith("pasted\nlog line")


def test_file_and_text_rejected(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("x")
    with pytest.raises(UsageError):
        input_reader.read("q", str(f), "text too", 5000, 1_000_000, stdin=FakeStdin(tty=True))
    with pytest.raises(InputError, match="empty"):
        input_reader.read("q", None, "   ", 5000, 1_000_000, stdin=FakeStdin(tty=True))


def test_missing_question():
    with pytest.raises(UsageError):
        input_reader.read("  ", None, None, 5000, 1_000_000, stdin=FakeStdin(tty=True))
