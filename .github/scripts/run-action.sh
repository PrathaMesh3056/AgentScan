#!/usr/bin/env bash
# Values arrive through the environment, never as executable shell source.
set -euo pipefail

case "$AGENTSCAN_COMMAND" in
  audit) positional="$AGENTSCAN_PATH" ;;
  scan) positional="$AGENTSCAN_TARGET_URL" ;;
  *) printf '%s\n' 'AgentScan command must be audit or scan.' >&2; exit 2 ;;
esac
if [[ -z "$positional" ]]; then
  printf '%s\n' 'AgentScan path or target URL must not be empty.' >&2
  exit 2
fi

args=("$AGENTSCAN_COMMAND")
severity="${AGENTSCAN_FAIL_ON^^}"
case "$severity" in
  "") ;;
  CRITICAL|HIGH|MEDIUM|LOW) args+=(--fail-on "$severity") ;;
  *) printf '%s\n' 'AgentScan fail-on must be CRITICAL, HIGH, MEDIUM, LOW, or empty.' >&2; exit 2 ;;
esac
if [[ -n "$AGENTSCAN_SARIF_OUTPUT" ]]; then
  args+=(--output "$AGENTSCAN_SARIF_OUTPUT")
elif [[ -n "$AGENTSCAN_JSON_OUTPUT" ]]; then
  args+=(--output "$AGENTSCAN_JSON_OUTPUT")
fi

# The terminator protects paths beginning with a dash from option parsing.
args+=(-- "$positional")
agentscan "${args[@]}"
