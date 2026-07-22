#!/usr/bin/env bash
# Long-lived, low-churn wrapper for hosts without a usable systemd service bus.
set -Eeuo pipefail

pause_seconds=${USF_FACTORY_SAFE_PAUSE_SECONDS:-900}
[[ "${pause_seconds}" =~ ^[0-9]+$ ]] || {
  printf 'USF_FACTORY_SAFE_PAUSE_SECONDS must be a non-negative integer\n' >&2
  exit 2
}

stopping=0
trap 'stopping=1' TERM INT HUP

while (( stopping == 0 )); do
  /root/usf-factory/scripts/run-safe-adaptive.sh || exit $?
  (( stopping == 0 )) || break
  sleep "${pause_seconds}" &
  wait $! || true
done
