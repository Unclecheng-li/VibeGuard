#!/bin/sh
set -eu

if [ "${1:-}" = "findings" ] && [ "${2:-}" = "serve" ]; then
  case "${VIBEGUARD_TELEMETRY_COLLECTION:-false}" in
    false|0|no|off|"")
      ;;
    true|1|yes|on)
      set -- "$@" --telemetry-collection
      if [ -n "${VIBEGUARD_TELEMETRY_MAX_EVENTS_PER_MINUTE:-}" ]; then
        set -- "$@" --telemetry-max-events-per-minute "$VIBEGUARD_TELEMETRY_MAX_EVENTS_PER_MINUTE"
      fi
      ;;
    *)
      echo "VIBEGUARD_TELEMETRY_COLLECTION must be true or false." >&2
      exit 64
      ;;
  esac
fi

exec node /opt/vibeguard/dist/cli.js "$@"
