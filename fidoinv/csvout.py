"""Appending inventory rows to a CSV file."""

from __future__ import annotations

import csv
from pathlib import Path

COLUMNS = [
    "timestamp",
    "token_label",
    "record_type",
    "product_name",
    "model",
    "aaguid",
    "usb_serial",
    "rp_id",
    "rp_name",
    "user_name",
    "user_display_name",
    "user_id",
    "credential_id",
    "cose_alg",
    "public_key",
    "public_key_cose",
    "cred_protect",
    "large_blob_key",
    "note",
]


def append_rows(path: Path, rows: list[dict[str, str]]) -> int:
    """Append rows; create the file with a header if new. Returns rows written.

    If the file already exists, its own header is used (unknown columns are left
    blank, extra keys dropped) so older files keep lining up.
    """
    path = Path(path)
    exists = path.is_file() and path.stat().st_size > 0
    fieldnames = COLUMNS
    if exists:
        with path.open("r", newline="", encoding="utf-8-sig") as f:
            header = next(csv.reader(f), None)
        if header:
            fieldnames = header
        # make sure we start on a new line
        with path.open("rb") as f:
            f.seek(-1, 2)
            last = f.read(1)
        if last not in (b"\n", b"\r"):
            with path.open("a", newline="", encoding="utf-8") as f:
                f.write("\r\n")
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, restval="", extrasaction="ignore")
        if not exists:
            w.writeheader()
        for r in rows:
            w.writerow(r)
    return len(rows)
