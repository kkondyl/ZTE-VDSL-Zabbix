#!/usr/bin/env bash
set -euo pipefail

PROXY="YOUR ZABBIX SERVER/PROXY"     # <-- change to your Zabbix Server or Proxy IP/DNS
ZBX_HOST="YOUR ZABBIX HOST"          # <-- must match the host name you created in Zabbix
MODEM_IP="YOUR ZTE IP"               # <-- modem address on the Pi’s LAN
USER="admin"                         # <-- modem username
PASS="YOUR PASSWORD"


JSON="$(python3 /mnt/zte/zte_vdsl.py -H "$MODEM_IP" -u "$USER" -p "$PASS" \
  | jq '{ok, data:{parsed:{dsl:.data.parsed.dsl }}}')"



# Optional: quick sanity check to avoid pushing empty/invalid payloads
if [[ -z "$JSON" ]] || ! jq -e . >/dev/null 2>&1 <<<"$JSON"; then
  echo "Invalid JSON, not sending." >&2
  exit 2
fi

if ! jq -e '.data.parsed.dsl' >/dev/null <<<"$JSON"; then
  echo "No parsed DSL data; not sending." >&2
  exit 3
fi


/usr/bin/zabbix_sender -z "$PROXY" -s "$ZBX_HOST" -k zte.dsl.json -o "$JSON" >/dev/null
