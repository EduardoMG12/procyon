#!/usr/bin/env bash
# Seeds crAPI with the two test accounts procyon test logs in as, and gives
# each its vehicle: crAPI e-mails a new user its VIN and pincode (to its own
# Mailhog), and the vehicle is added with them. They are test accounts of a
# disposable copy, not secrets.
#
# It writes run/.procyon.yaml: procyon.base.yaml plus A's vehicle ID under
# test.ids. crAPI lists vehicles under /vehicle/vehicles with a "uuid",
# which nothing in the spec ties to /vehicle/{vehicleId}/location, so the
# ID is declared, the way test.ids exists for.
set -euo pipefail
base=${1:-http://127.0.0.1:8888}
mail=${2:-http://127.0.0.1:8025}
password=Procyon-Test-1
for who in alice:9990000001 bob:9990000002; do
  name=${who%%:*} number=${who#*:}
  curl -sf -X POST "$base/identity/api/auth/signup" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$name\",\"email\":\"$name@procyon.test\",\"number\":\"$number\",\"password\":\"$password\"}" > /dev/null
done
for name in alice bob; do
  # The welcome e-mail may take a moment.
  vehicle=""
  for _ in $(seq 120); do
    vehicle=$(curl -sf "$mail/api/v2/messages" | python3 -c '
import json, quopri, re, sys
for m in json.load(sys.stdin)["items"]:
    if m["Content"]["Headers"].get("To") == [sys.argv[1]]:
        text = quopri.decodestring(m["Raw"]["Data"].encode()).decode("utf-8", "replace")
        found = re.search(r"VIN:\s*(\w{17})\s*and\s*Pincode:\s*(\d+)", re.sub(r"<[^>]+>", " ", text))
        if found:
            print(json.dumps({"vin": found[1], "pincode": found[2]}))
            break
' "$name@procyon.test")
    [ -n "$vehicle" ] && break
    sleep 1
  done
  [ -n "$vehicle" ] || { echo "no welcome e-mail for $name" >&2; exit 1; }
  token=$(curl -sf -X POST "$base/identity/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$name@procyon.test\",\"password\":\"$password\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
  curl -sf -X POST "$base/identity/api/v2/vehicle/add_vehicle" -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' -d "$vehicle" > /dev/null
  if [ "$name" = alice ]; then
    vehicle_id=$(curl -sf -H "Authorization: Bearer $token" "$base/identity/api/v2/vehicle/vehicles" |
      python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["uuid"])')
  fi
done
here=$(dirname "$0")
mkdir -p "$here/run"
{ cat "$here/procyon.base.yaml"; printf '  ids:\n    vehicleId: ["%s"]\n' "$vehicle_id"; } > "$here/run/.procyon.yaml"
echo "crAPI seeded: alice@procyon.test and bob@procyon.test, each with a vehicle; config in $here/run/"
