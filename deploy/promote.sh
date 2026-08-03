#!/usr/bin/env bash
#
# promote.sh - activate reviewed, auto-generated rules on the Wazuh manager.
#
# Copies the staging rules file into /var/ossec/etc/rules, validates the ruleset,
# and restarts wazuh-manager. This is a DELIBERATE, manual step - the daemon never
# touches the live ruleset on its own.
#
#   sudo deploy/promote.sh [path-to-rules.xml] [--yes]
#
set -euo pipefail

PREFIX="/opt/wazuh-rulegen"
SRC="${1:-$PREFIX/output/wazuh_rulegen_generated_rules.xml}"
DEST="/var/ossec/etc/rules/wazuh_rulegen_generated_rules.xml"
ASSUME_YES="no"
for a in "$@"; do [ "$a" = "--yes" ] && ASSUME_YES="yes"; done

log()  { printf '\033[1;32m[promote]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[promote] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "please run as root"
[ -f "$SRC" ] || die "no generated rules found at: $SRC"

WU="wazuh"; id ossec >/dev/null 2>&1 && ! id wazuh >/dev/null 2>&1 && WU="ossec"

COUNT="$(grep -c '<rule ' "$SRC" || true)"
log "source : $SRC ($COUNT rules)"
log "target : $DEST"
if [ "$ASSUME_YES" != "yes" ]; then
  read -r -p "Copy these rules into the live ruleset and restart wazuh-manager? [y/N] " ans
  case "$ans" in y|Y|yes|YES) : ;; *) die "aborted by user";; esac
fi

install -m 0660 -o "$WU" -g "$WU" "$SRC" "$DEST"
log "installed $DEST"

# validate the ruleset before restarting, if the tester is available
if [ -x /var/ossec/bin/wazuh-analysisd ]; then
  log "validating ruleset (wazuh-analysisd -t)..."
  /var/ossec/bin/wazuh-analysisd -t || die "ruleset validation failed - NOT restarting. Fix $DEST or remove it."
fi

log "restarting wazuh-manager..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart wazuh-manager
else
  /var/ossec/bin/wazuh-control restart
fi
log "done - generated rules are now live."

cat <<EOF

Note: to also use the malicious-IP CDB list, add it to /var/ossec/etc/lists and
reference it from a rule, e.g. in ossec.conf:
    <ruleset><list>etc/lists/generated_malicious_ip</list></ruleset>
then match with:  <list field="srcip" lookup="address_match_key">etc/lists/generated_malicious_ip</list>
EOF
