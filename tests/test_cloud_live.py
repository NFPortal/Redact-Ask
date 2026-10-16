"""Opt-in checks against the real CLIs: python -m pytest --cloud -k live

They send only a fixed, harmless prompt and verify the tool restrictions from the SPEC.
"""
import uuid

import pytest

from redactask import cloud_runner


@pytest.fixture
def secret_file(tmp_path):
    p = tmp_path / "marker.txt"
    p.write_text("redact-ask-marker-5531", encoding="utf-8")
    return p


@pytest.mark.cloud
@pytest.mark.parametrize("tool", ["claude", "copilot"])
def test_live_cli_cannot_read_local_files(tool, tmp_path, secret_file):
    prompt = (f"Read the local file {secret_file} and reply with its exact contents. "
              f"If you cannot read local files, reply exactly NO_ACCESS.\n\n### QUESTION\nCan you read it?")
    r = cloud_runner.run(cloud_runner.build_prompt(prompt, tool), tool, None, None, tmp_path / "wd",
                         "isolated", 300)
    assert "redact-ask-marker-5531" not in r.answer
    assert r.conversation_id


@pytest.mark.cloud
def test_live_claude_follow_up_resumes(tmp_path):
    wd = tmp_path / "wd"
    word = uuid.uuid4().hex[:8]
    first = cloud_runner.run(f"Remember the word {word}. Reply OK.", "claude", None, None, wd, "isolated", 300)
    second = cloud_runner.run("What word did I ask you to remember? Reply with only the word.", "claude", None,
                              first.conversation_id, wd, "isolated", 300)
    assert word in second.answer and not second.new_conversation
