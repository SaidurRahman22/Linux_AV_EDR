"""Log sources: batch readers for alerts.json(.gz) and a real-time file tailer.

Wazuh writes one JSON object per line to ``alerts.json``. The tailer follows the
active file, tolerates partial trailing lines, and detects log rotation /
truncation (inode change or shrink) so the daemon keeps working across the
manager's nightly ``logrotate``.
"""

from __future__ import annotations

import gzip
import json
import os
from typing import Iterator, Optional


def _open_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def iter_alerts(path: str) -> Iterator[dict]:
    """Yield parsed alert dicts from one alerts.json / .gz file (batch mode)."""
    with _open_text(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def iter_alerts_multi(paths: list[str]) -> Iterator[dict]:
    for p in paths:
        if os.path.exists(p):
            yield from iter_alerts(p)


def discover_archived_alerts(alerts_dir: str) -> list[str]:
    """Find rotated alerts (…/alerts/<year>/<Mon>/ossec-alerts-NN.json[.gz])."""
    found: list[str] = []
    if not os.path.isdir(alerts_dir):
        return found
    for root, _dirs, files in os.walk(alerts_dir):
        for name in files:
            if name.startswith("ossec-alerts-") and (name.endswith(".json") or name.endswith(".json.gz")):
                found.append(os.path.join(root, name))
    found.sort()
    return found


class Tailer:
    """Follow a growing text file line-by-line, surviving rotation/truncation.

    ``poll()`` returns a list of newly-completed lines (without trailing '\\n').
    A partial final line is buffered until its newline arrives.
    """

    def __init__(self, path: str, from_start: bool = False,
                 start_offset: Optional[int] = None,
                 start_inode: Optional[tuple] = None):
        self.path = path
        self._fh = None
        self._inode: Optional[tuple] = None
        self._buf = ""
        self.offset = 0
        self._from_start = from_start
        self._resume_offset = start_offset
        self._resume_inode = start_inode

    def _stat_key(self, st: os.stat_result) -> tuple:
        return (st.st_dev, st.st_ino)

    def _open(self, seek_end: bool) -> None:
        self._fh = _open_text(self.path)
        st = os.fstat(self._fh.fileno())
        self._inode = self._stat_key(st)
        if seek_end:
            self._fh.seek(0, os.SEEK_END)
        self.offset = self._fh.tell()

    def _open_resume(self, st: os.stat_result) -> None:
        """Reopen honoring a persisted (inode, offset) if the file still matches."""
        self._fh = _open_text(self.path)
        self._inode = self._stat_key(st)
        same_file = (self._resume_inode is None or tuple(self._resume_inode) == self._inode)
        if same_file and self._resume_offset is not None and self._resume_offset <= st.st_size:
            self._fh.seek(self._resume_offset)
        elif self._from_start:
            self._fh.seek(0)
        else:
            self._fh.seek(0, os.SEEK_END)
        self.offset = self._fh.tell()
        self._resume_offset = None
        self._resume_inode = None

    def poll(self) -> list[str]:
        lines: list[str] = []
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return lines

        if self._fh is None:
            if self._resume_offset is not None or self._resume_inode is not None:
                self._open_resume(st)
            else:
                self._open(seek_end=not self._from_start)
        else:
            key = self._stat_key(st)
            if key != self._inode or st.st_size < self.offset:
                # rotated (new inode) or truncated -> start reading the new file
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._buf = ""
                self._open(seek_end=False)

        chunk = self._fh.read()
        if chunk:
            self.offset = self._fh.tell()
            self._buf += chunk
            parts = self._buf.split("\n")
            self._buf = parts.pop()
            lines.extend(p for p in parts if p.strip())
        return lines

    @property
    def state(self) -> dict:
        return {"path": self.path, "offset": self.offset, "inode": list(self._inode) if self._inode else None}

    def close(self) -> None:
        if self._fh:
            try:
                self._fh.close()
            finally:
                self._fh = None


def parse_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None
