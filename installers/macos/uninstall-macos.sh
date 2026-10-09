#!/bin/bash
set -euo pipefail
# Self-locating: this script lives at $ROOT/uninstall.sh in every install
# layout (machine-wide /opt/nc or a per-user tree). Never hardcode the root.
ROOT="$(cd "$(dirname "$0")" && pwd)"
PLIST=/Library/LaunchDaemons/com.nc.client.plist
IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1
# Safety: only ever delete a real agent tree (marker files must exist).
[ -f "$ROOT/config/nc-client.env" ] || [ -d "$ROOT/app" ] || { echo 'not an NC install root; refusing' >&2; exit 1; }

if [ "$IS_ROOT" -eq 1 ]; then
  launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
  launchctl disable system/com.nc.client >/dev/null 2>&1 || true
  # Faz 10: retire the privileged-helper daemon alongside the agent.
  launchctl bootout system/com.nc.privileged-helper >/dev/null 2>&1 || true
  launchctl disable system/com.nc.privileged-helper >/dev/null 2>&1 || true
  rm -f /Library/LaunchDaemons/com.nc.privileged-helper.plist "$ROOT/libexec/nc-darwin-peercred"
fi
# Faz A: user-mode installs run as a per-user LaunchAgent; retire it too.
_op="$(awk -F= '$1=="NC_OPERATOR_USER"{print substr($0,index($0,"=")+1);exit}' "$ROOT/config/nc-client.env" 2>/dev/null)"
[ -n "$_op" ] || _op="$(stat -f %Su "$ROOT" 2>/dev/null || true)"
[ -n "$_op" ] || _op="$(id -un 2>/dev/null || true)"
if [ -n "$_op" ] && [ "$_op" != root ] && dscl . -read "/Users/$_op" >/dev/null 2>&1; then
  _op_uid="$(id -u "$_op")"
  _op_home="$(dscl . -read "/Users/$_op" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
  launchctl bootout "gui/$_op_uid/com.nc.client" >/dev/null 2>&1 || true
  launchctl disable "gui/$_op_uid/com.nc.client" >/dev/null 2>&1 || true
  rm -f "$_op_home/Library/LaunchAgents/com.nc.client.plist"
  unset _op_uid _op_home
fi
unset _op

_nc_pids=''
while IFS= read -r _line; do
  _pid="$(printf '%s\\n' "$_line" | awk '{print $1}')"
  _cmd="$(printf '%s\\n' "$_line" | cut -d' ' -f2-)"
  case "$_cmd" in
    *"$ROOT/app/launcher.mjs"*|*"$ROOT/app/client.mjs"*)
      [ "$_pid" = "$$" ] || _nc_pids="$_nc_pids $_pid"
      ;;
  esac
done <<EOF
$(ps -axo pid=,command=)
EOF
for _pid in $_nc_pids; do kill -TERM "$_pid" 2>/dev/null || true; done
for _wait in 1 2 3 4 5 6 7 8 9 10; do
  _alive=''
  for _pid in $_nc_pids; do kill -0 "$_pid" 2>/dev/null && _alive="$_alive $_pid" || true; done
  [ -z "$_alive" ] && break
  sleep 0.25
done
for _pid in $_alive; do kill -KILL "$_pid" 2>/dev/null || true; done

if [ "$IS_ROOT" -eq 1 ]; then
  rm -f "$PLIST"
  rm -f /etc/sudoers.d/nc-uninstall
fi
rm -rf -- "$ROOT"

echo 'NC client uninstalled from macOS. The dedicated _nc service identity is intentionally retained.'
