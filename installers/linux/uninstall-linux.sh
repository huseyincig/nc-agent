#!/bin/bash
set -euo pipefail
# Self-locating: this script lives at $ROOT/uninstall.sh in every install
# layout (machine-wide /opt/nc or a per-user tree). Never hardcode the root.
ROOT="$(cd "$(dirname "$0")" && pwd)"
UNIT=/etc/systemd/system/nc-client.service
IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1
# Safety: only ever delete a real agent tree (marker files must exist).
[ -f "$ROOT/config/nc-client.env" ] || [ -d "$ROOT/app" ] || { echo 'not an NC install root; refusing' >&2; exit 1; }

if [ "$IS_ROOT" -eq 1 ]; then
  systemctl disable --now nc-client.service >/dev/null 2>&1 || true
  systemctl disable --now nc-privileged-helper.socket >/dev/null 2>&1 || true
  systemctl stop nc-privileged-helper.service >/dev/null 2>&1 || true
fi
# Faz A: user-mode installs run under `systemd --user`; retire that unit too.
if grep -q '^NC_SERVICE_MODE=user' "$ROOT/config/nc-client.env" 2>/dev/null; then
  _op="$(awk -F= '$1=="NC_OPERATOR_USER"{print substr($0,index($0,"=")+1);exit}' "$ROOT/config/nc-client.env" 2>/dev/null)"
  # Fallback: env stamp carries the mode; owner of the tree is the operator.
  [ -n "$_op" ] || _op="$(stat -c '%U' "$ROOT" 2>/dev/null || true)"
  [ -n "$_op" ] || _op="$(id -un 2>/dev/null || true)"
  _run_userbus(){
    if [ "$IS_ROOT" -eq 1 ] && [ -n "$_op" ] && [ "$_op" != root ] && id "$_op" >/dev/null 2>&1; then
      _op_uid="$(id -u "$_op")"
      runuser -u "$_op" -- env XDG_RUNTIME_DIR="/run/user/$_op_uid" "$@"
    else
      XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" "$@"
    fi
  }
  _run_userbus systemctl --user disable --now nc-client.service >/dev/null 2>&1 || true
  _op_home=''
  if [ -n "$_op" ] && [ "$_op" != root ]; then _op_home="$(getent passwd "$_op" 2>/dev/null | cut -d: -f6)"; fi
  [ -n "$_op_home" ] || _op_home="$HOME"
  rm -f "$_op_home/.config/systemd/user/nc-client.service"
  _run_userbus systemctl --user daemon-reload >/dev/null 2>&1 || true
  unset _op _op_uid _op_home
  unset -f _run_userbus
fi

_nc_pids=()
for _proc in /proc/[0-9]*; do
  [ -r "$_proc/cmdline" ] || continue
  _cmd="$(tr '\0' ' ' < "$_proc/cmdline" 2>/dev/null || true)"
  case "$_cmd" in
    *"$ROOT/app/launcher.mjs"*|*"$ROOT/app/client.mjs"*)
      _pid="${_proc##*/}"
      if [ "$_pid" != "$$" ]; then _nc_pids+=("$_pid"); fi
      ;;
  esac
done
for _pid in "${_nc_pids[@]}"; do kill -TERM "$_pid" 2>/dev/null || true; done
for _wait in 1 2 3 4 5 6 7 8 9 10; do
  _alive=()
  for _pid in "${_nc_pids[@]}"; do kill -0 "$_pid" 2>/dev/null && _alive+=("$_pid") || true; done
  [ "${#_alive[@]}" -eq 0 ] && break
  sleep 0.25
done
for _pid in "${_alive[@]}"; do kill -KILL "$_pid" 2>/dev/null || true; done

if [ "$IS_ROOT" -eq 1 ]; then
  rm -f "$UNIT" /etc/systemd/system/nc-privileged-helper.socket /etc/systemd/system/nc-privileged-helper.service /etc/tmpfiles.d/nc-privileged-helper.conf
  rm -f /run/nc/privileged-helper-v1.sock 2>/dev/null || true
  rmdir /run/nc 2>/dev/null || true
  systemctl daemon-reload
  systemctl reset-failed nc-client.service >/dev/null 2>&1 || true
fi
rm -rf -- "$ROOT"

echo 'NC client uninstalled from Linux. Dedicated service user/group are intentionally retained.'
