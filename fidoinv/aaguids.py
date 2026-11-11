"""AAGUID -> authenticator model name lookup.

A small bundled table (aaguids.json) covers the brands this tool was written
for. Names come from the community list at
https://github.com/passkeydeveloper/passkey-authenticator-aaguids, which is
largely derived from the FIDO Alliance Metadata Service (MDS).
`fidoinv update-aaguids` downloads the full list into a per-user cache file
that is consulted first.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from importlib import resources
from pathlib import Path

COMBINED_URL = (
    "https://raw.githubusercontent.com/passkeydeveloper/"
    "passkey-authenticator-aaguids/main/combined_aaguid.json"
)


def cache_path() -> Path:
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "fidoinv" / "aaguids.json"


_table: dict[str, str] | None = None


def _load() -> dict[str, str]:
    global _table
    if _table is None:
        table: dict[str, str] = {}
        data = resources.files("fidoinv").joinpath("aaguids.json").read_text("utf-8")
        table.update(json.loads(data))
        cp = cache_path()
        if cp.is_file():
            try:
                table.update(json.loads(cp.read_text("utf-8")))
            except (OSError, ValueError):
                pass
        _table = {k.lower(): v for k, v in table.items()}
    return _table


def lookup(aaguid: str) -> str:
    """Return the model name for an AAGUID string, or '' if unknown."""
    return _load().get(str(aaguid).lower(), "")


def update(url: str = COMBINED_URL) -> tuple[Path, int]:
    """Download the full community AAGUID list into the cache. Returns (path, count)."""
    with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 - fixed https URL
        raw = json.loads(r.read().decode("utf-8"))
    names = {k.lower(): (v.get("name") if isinstance(v, dict) else str(v)) for k, v in raw.items()}
    names = {k: v for k, v in names.items() if v}
    cp = cache_path()
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(json.dumps(names, indent=1, sort_keys=True), "utf-8")
    global _table
    _table = None
    return cp, len(names)
