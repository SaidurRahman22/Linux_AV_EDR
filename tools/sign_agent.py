#!/usr/bin/env python3
"""Offline Ed25519 signing for Padakhep Sentinel agent builds (SEN-002).

The agent verifies every downloaded build against a signature made with a private
key that lives OFFLINE (never on the control plane). A compromised or MITM'd
server therefore cannot push code the agents will run. Pure-stdlib (no pip dep)
so it matches the agents' constraint; the verify half is embedded in the agents.

    python tools/sign_agent.py keygen                 # once: make a keypair
    python tools/sign_agent.py pubkey                 # print the pinned public key (hex)
    python tools/sign_agent.py sign <file> [<file>..] # write <file>.sig for each build

Keys live in tools/keys/ (gitignored). In production keep the private key on an
offline/HSM host, not on the build box.
"""
from __future__ import annotations

import hashlib
import os
import sys

# --- Ed25519 (public-domain reference, using Python's fast built-in pow) --------
_q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x): return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_B = (_xrecover(_By) % _q, _By % _q)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    dd = _d * x1 * x2 * y1 * y2
    return ((x1 * y2 + x2 * y1) * _inv(1 + dd) % _q,
            (y1 * y2 + x1 * x2) * _inv(1 - dd) % _q)


def _scalarmult(P, e):
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    return _edwards(Q, P) if e & 1 else Q


def _bit(h, i): return (h[i // 8] >> (i % 8)) & 1


def _encodeint(y): return y.to_bytes(32, "little")


def _encodepoint(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _Hint(m):
    h = hashlib.sha512(m).digest()
    return sum(2 ** i * _bit(h, i) for i in range(512))


def _clamp(h):
    return 2 ** 254 + sum(2 ** i * _bit(h, i) for i in range(3, 254))


def publickey(seed: bytes) -> bytes:
    return _encodepoint(_scalarmult(_B, _clamp(hashlib.sha512(seed).digest())))


def sign(seed: bytes, pub: bytes, msg: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = _clamp(h)
    r = _Hint(h[32:64] + msg)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pub + msg) * a) % _L
    return _encodepoint(R) + _encodeint(S)


# --- CLI ------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_KEYDIR = os.path.join(_HERE, "keys")
_SEED = os.path.join(_KEYDIR, "agent_ed25519.seed")
_PUB = os.path.join(_KEYDIR, "agent_ed25519.pub")


def _load_seed() -> bytes:
    with open(_SEED, "rb") as f:
        return f.read()


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "keygen":
        os.makedirs(_KEYDIR, exist_ok=True)
        if os.path.exists(_SEED):
            print("refusing to overwrite existing key at", _SEED); return
        seed = os.urandom(32)
        pub = publickey(seed)
        with open(_SEED, "wb") as f:
            f.write(seed)
        os.chmod(_SEED, 0o600)
        with open(_PUB, "w") as f:
            f.write(pub.hex())
        print("keypair written to", _KEYDIR)
        print("PUBLIC KEY (embed this in the agents):", pub.hex())
    elif cmd == "pubkey":
        print(publickey(_load_seed()).hex())
    elif cmd == "sign":
        seed = _load_seed()
        pub = publickey(seed)
        for path in sys.argv[2:]:
            with open(path, "rb") as f:
                data = f.read()
            sig = sign(seed, pub, data)
            with open(path + ".sig", "w") as f:
                f.write(sig.hex())
            print(f"signed {path} -> {path}.sig ({len(data)} bytes)")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
