"""Padakhep Sentinel — minimal Linux AV agent (Increment 3, basic).

Stdlib-only. Enrolls with the control plane, pulls the IOC/signature/behavior
policy, scans locally (file hash + signature match + auth-log & process behavior),
and reports detections. Detect-only; no blocking (SRS safe-response comes later).
"""
__version__ = "0.1.0"
