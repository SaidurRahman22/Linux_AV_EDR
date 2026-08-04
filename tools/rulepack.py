"""Pack/unpack the YARA rule set to an AV-safe blob.

Endpoint antivirus (ESET, Defender, ...) quarantines plaintext .yar files
because they legitimately contain malware *signature strings*. We ship the
rules as a gzip+base64 blob (opaque to signature scanners) and decode them at
load time on the control plane.

    python tools/rulepack.py pack     # av_content/yara/*.yar -> av_content/rulepack.b64
    python tools/rulepack.py unpack   # av_content/rulepack.b64 -> av_content/yara/*.yar (for editing)
"""

from __future__ import annotations

import base64
import gzip
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
YDIR = os.path.join(_ROOT, "av_content", "yara")
BLOB = os.path.join(_ROOT, "av_content", "rulepack.b64")
BEH_JSON = os.path.join(_ROOT, "av_content", "behaviors.json")
BEH_BLOB = os.path.join(_ROOT, "av_content", "behaviors.b64")
SEP = "\n// ===== %s =====\n"


def _pack_file(src: str, dst: str) -> int:
    with open(src, "rb") as f:
        raw = f.read()
    with open(dst, "wb") as f:
        f.write(base64.b64encode(gzip.compress(raw, 9)))
    return len(raw)


def _unpack_file(src: str, dst: str) -> None:
    with open(src, "rb") as f:
        raw = gzip.decompress(base64.b64decode(f.read()))
    with open(dst, "wb") as f:
        f.write(raw)


def pack() -> None:
    parts = []
    for fn in sorted(os.listdir(YDIR)):
        if fn.endswith(".yar"):
            with open(os.path.join(YDIR, fn), encoding="utf-8") as f:
                parts.append((SEP % fn) + f.read())
    text = "\n".join(parts)
    n = len(re.findall(r"(?m)^rule\s+\w", text))
    raw = gzip.compress(text.encode("utf-8"), 9)
    with open(BLOB, "wb") as f:
        f.write(base64.b64encode(raw))
    print(f"packed {n} rules from {len(parts)} files -> {os.path.relpath(BLOB, _ROOT)} "
          f"({os.path.getsize(BLOB)} bytes)")
    if os.path.isfile(BEH_JSON):
        _pack_file(BEH_JSON, BEH_BLOB)
        print(f"packed behaviors -> {os.path.relpath(BEH_BLOB, _ROOT)} ({os.path.getsize(BEH_BLOB)} bytes)")


def unpack() -> None:
    with open(BLOB, "rb") as f:
        text = gzip.decompress(base64.b64decode(f.read())).decode("utf-8")
    os.makedirs(YDIR, exist_ok=True)
    blocks = re.split(r"(?m)^// ===== (\S+\.yar) =====$", text)
    # blocks = ['', fname1, body1, fname2, body2, ...]
    written = 0
    for i in range(1, len(blocks), 2):
        fn, body = blocks[i], blocks[i + 1]
        with open(os.path.join(YDIR, fn), "w", encoding="utf-8") as f:
            f.write(body.strip() + "\n")
        written += 1
    print(f"unpacked {written} files into {os.path.relpath(YDIR, _ROOT)}")
    if os.path.isfile(BEH_BLOB):
        _unpack_file(BEH_BLOB, BEH_JSON)
        print(f"unpacked behaviors -> {os.path.relpath(BEH_JSON, _ROOT)}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "pack"
    (pack if cmd == "pack" else unpack)()
