#!/usr/bin/env bash
# Seeds crAPI with the two test accounts procyon test logs in as. They are
# test accounts of a disposable copy, not secrets.
set -euo pipefail
base=${1:-http://127.0.0.1:8888}
for who in alice:9990000001 bob:9990000002; do
  name=${who%%:*} number=${who#*:}
  curl -sf -X POST "$base/identity/api/auth/signup" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$name\",\"email\":\"$name@procyon.test\",\"number\":\"$number\",\"password\":\"Procyon-Test-1\"}" > /dev/null
done
echo "crAPI seeded: alice@procyon.test and bob@procyon.test"
