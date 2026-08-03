#!/usr/bin/env python3
"""Convenience launcher so you can run from a checkout without installing.

    python run.py scan  -c config.local.json
    python run.py run   -c config.json
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wazuh_rulegen.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
