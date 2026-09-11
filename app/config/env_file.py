"""
app/config/env_file.py
──────────────────────
Safe persistence for the console's API-key manager.

Writes to the repo's gitignored `.env` so a pasted key survives browser
refreshes and server restarts. Security posture:
  - atomic replace (temp file + os.replace) — no torn writes
  - 0600 permissions on the file
  - only the target variable is touched; every other line is preserved
  - the file is gitignored; nothing here is ever logged or exported
"""

import os


def save_env_var(path: str, name: str, value: str) -> None:
    """Set `name=value` in the env file, preserving all other lines."""
    lines: list[str] = []
    if os.path.exists(path):
        with open(path) as f:
            lines = f.read().splitlines()
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith(f"{name}="):
            lines[i] = f"{name}={value}"
            found = True
            break
    if not found:
        lines.append(f"{name}={value}")
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.environ[name] = value


def remove_env_var(path: str, name: str) -> bool:
    """Remove `name=...` from the env file. Returns True if a line was removed."""
    if not os.path.exists(path):
        return False
    with open(path) as f:
        lines = f.read().splitlines()
    kept = [line for line in lines if not line.strip().startswith(f"{name}=")]
    removed = len(kept) != len(lines)
    if removed:
        tmp = f"{path}.tmp"
        with open(tmp, "w") as f:
            f.write("\n".join(kept) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    os.environ.pop(name, None)
    return removed
