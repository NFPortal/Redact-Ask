import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from redactask import config  # noqa: E402

CORPUS = ROOT / "tests" / "corpus"



def pytest_addoption(parser):
    parser.addoption("--cloud", action="store_true", help="also run tests that call the real Claude/Copilot CLIs")


def pytest_collection_modifyitems(config, items):
    run_cloud = config.getoption("--cloud")
    for item in items:
        if "cloud" in item.keywords and not run_cloud:
            item.add_marker(pytest.mark.skip(reason="needs --cloud (calls the real CLIs)"))


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Every test gets its own config/data folders and never touches the real keyring."""
    home = tmp_path / "home"
    monkeypatch.setenv("REDACT_ASK_HOME", str(home))
    monkeypatch.setenv("REDACT_ASK_KEY_FILE_ONLY", "1")
    return home


@pytest.fixture
def cfg():
    return config.from_dict({})


def gliner_available() -> bool:
    try:
        from huggingface_hub import try_to_load_from_cache
        return try_to_load_from_cache("nvidia/gliner-pii", "gliner_config.json") not in (None,)
    except Exception:
        return False


requires_gliner = pytest.mark.skipif(not gliner_available(), reason="nvidia/gliner-pii model not downloaded")
