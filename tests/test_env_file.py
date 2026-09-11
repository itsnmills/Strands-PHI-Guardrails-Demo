"""
tests/test_env_file.py
──────────────────────
API-key persistence helpers: atomic, least-touch env-file writes.

Invariants:
  - only the target variable is modified; all other lines byte-preserved
  - new variables are appended
  - writes are atomic with 0600 permissions
  - remove strips exactly the target line
  - the in-process environment is updated alongside the file
"""

import os
import stat

from app.config.env_file import save_env_var, remove_env_var


def test_updates_existing_variable_preserving_other_lines(tmp_path):
    env = tmp_path / ".env"
    env.write_text("OPENCODE_API_KEY=old\nPHI_DEMO_MODEL=deepseek-v4.1-flash\n# comment\n")
    save_env_var(str(env), "OPENCODE_API_KEY", "new-key-value")
    content = env.read_text()
    assert "OPENCODE_API_KEY=new-key-value" in content
    assert "PHI_DEMO_MODEL=deepseek-v4.1-flash" in content
    assert "# comment" in content
    assert "old" not in content


def test_appends_when_missing(tmp_path):
    env = tmp_path / ".env"
    env.write_text("PHI_DEMO_MODEL=x\n")
    save_env_var(str(env), "OPENCODE_API_KEY", "fresh")
    assert env.read_text().splitlines()[-1] == "OPENCODE_API_KEY=fresh"


def test_creates_file_when_absent(tmp_path):
    env = tmp_path / ".env"
    save_env_var(str(env), "OPENCODE_API_KEY", "k")
    assert env.read_text().strip() == "OPENCODE_API_KEY=k"


def test_atomic_write_is_0600(tmp_path):
    env = tmp_path / ".env"
    env.write_text("A=1\n")
    save_env_var(str(env), "OPENCODE_API_KEY", "k")
    mode = stat.S_IMODE(os.stat(env).st_mode)
    assert mode == 0o600
    assert not (tmp_path / ".env.tmp").exists()


def test_in_process_environment_updated(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENCODE_API_KEY", raising=False)
    save_env_var(str(tmp_path / ".env"), "OPENCODE_API_KEY", "runtime")
    assert os.environ["OPENCODE_API_KEY"] == "runtime"


def test_remove_strips_only_target(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("OPENCODE_API_KEY=k\nPHI_DEMO_MODEL=m\n")
    monkeypatch.setenv("OPENCODE_API_KEY", "k")
    assert remove_env_var(str(env), "OPENCODE_API_KEY") is True
    assert env.read_text().strip() == "PHI_DEMO_MODEL=m"
    assert "OPENCODE_API_KEY" not in os.environ
    assert remove_env_var(str(env), "OPENCODE_API_KEY") is False


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call(["pytest", "-q", __file__]))
