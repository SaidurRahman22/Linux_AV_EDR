"""Enable ``python -m wazuh_rulegen ...``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
