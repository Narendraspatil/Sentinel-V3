import os, sys, tempfile
d = tempfile.mkdtemp(prefix="sentinel-test-")
os.environ.update(SENTINEL_DATA_DIR=d, SENTINEL_ALLOW_INSECURE_STORE="1", SENTINEL_ALLOW_HTTP="1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import pytest

@pytest.fixture
def datadir(tmp_path, monkeypatch):
    from sentinel import settings
    for n, v in dict(DATA_DIR=str(tmp_path), CONFIG_PATH=str(tmp_path / "config.json"), SECRET_PATH=str(tmp_path / "secret.bin"),
                     BUFFER_PATH=str(tmp_path / "events.db"), STATE_PATH=str(tmp_path / "state.json"), POLICY_PATH=str(tmp_path / "policy.json")).items():
        monkeypatch.setattr(settings, n, v)
    return tmp_path
