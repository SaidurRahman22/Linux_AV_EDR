"""wazuh_rulegen - Wazuh detection-rule generator.

Reads a Wazuh manager's alert stream (``/var/ossec/logs/alerts/alerts.json``),
detects suspicious activity (brute force, malicious IPs, malicious artifacts)
and emits ready-to-use Wazuh XML detection rules plus CDB IOC lists.

Two run modes:
  * ``scan`` - one-shot batch over existing logs.
  * ``run``  - daemon that tails the alert file and generates rules in real time.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
