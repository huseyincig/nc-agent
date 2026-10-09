#!/usr/bin/env bash
set -euo pipefail
ROOT="${NC_ROOT:-/opt/nc}"
UNIT=/etc/systemd/system/nc-client.service
SRC="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
# Idempotent system-level refresh for `install.sh --update` (single source).
# `install-linux.sh --upgrade` refreshes journal membership, directory
# ownership/permissions and privileged-helper units without touching client
# identity or data. All steps are diff-checked (already/skip logs) and safe
# to run repeatedly. User installs never touch usermod; non-root system
# refresh skips root-only steps with `system-level skipped (needs root)`.
NC_UPGRADE_MODE=0
if [ "${1:-}" = "--upgrade" ]; then
  NC_UPGRADE_MODE=1
fi
HELPER_SOCKET="${NC_HELPER_SOCKET:-/etc/systemd/system/nc-privileged-helper.socket}"
HELPER_SERVICE="${NC_HELPER_SERVICE:-/etc/systemd/system/nc-privileged-helper.service}"
HELPER_TMPFILES="${NC_HELPER_TMPFILES:-/etc/tmpfiles.d/nc-privileged-helper.conf}"
# Privilege model: root installs target the machine tree; anything else is a
# per-user install into the operator's own tree with zero elevation.
# NC_USER_INSTALL=1 forces the user path explicitly. NC_ROOT overrides the
# target in both paths.
USER_INSTALL=0
if [ "$(id -u)" -ne 0 ]; then USER_INSTALL=1; fi
if [ "${NC_USER_INSTALL:-0}" = "1" ]; then USER_INSTALL=1; fi
if [ "$(id -u)" -ne 0 ] && [ "${NC_SYSTEM_INSTALL:-0}" = "1" ]; then
  if [ "$NC_UPGRADE_MODE" -eq 1 ]; then
    :
  else
    echo 'root required for system install' >&2; exit 1
  fi
fi
if [ "$USER_INSTALL" -eq 1 ] && [ -z "${NC_ROOT:-}" ]; then
  _data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
  [ -n "${HOME:-}" ] && [ -d "$HOME" ] || { echo 'user install needs a home directory' >&2; exit 1; }
  ROOT="$_data_home/nc"
  unset _data_home
fi
# Node.js 24+: system runtime when present, otherwise a portable runtime
# fetched from upstream nodejs.org into the install tree (the hub never
# carries runtimes; the install tree keeps ~250KB of agent payload).
ensure_node(){
  NODE_BIN="$(command -v node || true)"
  if [ -z "$NODE_BIN" ] && [ -x "$ROOT/tools/node/bin/node" ]; then NODE_BIN="$ROOT/tools/node/bin/node"; fi
  if [ -n "$NODE_BIN" ]; then
    NODE_MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
    case "$NODE_MAJOR" in ''|*[!0-9]*) NODE_MAJOR=0 ;; esac
    if [ "$NODE_MAJOR" -ge 24 ] 2>/dev/null; then return 0; fi
  fi
  _os="$(uname -s)"; _arch="$(uname -m)"
  case "$_os/$_arch" in
    Linux/x86_64) _plat=linux-x64; _ext=tar.xz ;;
    Linux/aarch64) _plat=linux-arm64; _ext=tar.xz ;;
    Darwin/x86_64) _plat=darwin-x64; _ext=tar.gz ;;
    Darwin/arm64) _plat=darwin-arm64; _ext=tar.gz ;;
    *) echo "Node.js 24+ required (no portable build for $_os/$_arch)" >&2; exit 1 ;;
  esac
  if command -v curl >/dev/null 2>&1; then _dl="curl -fsSL"; elif command -v wget >/dev/null 2>&1; then _dl="wget -qO-"; else echo 'Node.js 24+ required (no curl/wget for portable bootstrap)' >&2; exit 1; fi
  echo 'Node.js 24+ not found; fetching portable runtime from nodejs.org...' >&2
  if command -v python3 >/dev/null 2>&1; then
    _ver="$($_dl https://nodejs.org/dist/index.json 2>/dev/null | python3 -c 'import json,sys; print([e["version"] for e in json.load(sys.stdin) if e["version"].startswith("v24.") and e.get("lts")][0])' 2>/dev/null || true)"
  else
    _ver="$($_dl https://nodejs.org/dist/index.json 2>/dev/null | grep -o '"version":"v24[^"]*"' | head -n1 | cut -d'"' -f4 || true)"
  fi
  [ -n "$_ver" ] || { echo 'Node.js 24+ required (portable index unreadable)' >&2; exit 1; }
  _tools="$ROOT/tools/node"
  _tmp="$(mktemp -d)"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "https://nodejs.org/dist/$_ver/node-$_ver-$_plat.$_ext" -o "$_tmp/node.$_ext" || { echo 'Node.js 24+ required (portable download failed)' >&2; exit 1; }
  else
    wget -q "https://nodejs.org/dist/$_ver/node-$_ver-$_plat.$_ext" -O "$_tmp/node.$_ext" || { echo 'Node.js 24+ required (portable download failed)' >&2; exit 1; }
  fi
  mkdir -p "$_tools"
  tar -xf "$_tmp/node.$_ext" -C "$_tools" --strip-components=1 || { echo 'Node.js 24+ required (portable extract failed)' >&2; exit 1; }
  rm -rf "$_tmp"
  NODE_BIN="$_tools/bin/node"
  export PATH="$_tools/bin:$PATH"
  NODE_MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [ "$NODE_MAJOR" -ge 24 ] 2>/dev/null || { echo 'Node.js 24+ required (portable runtime failed to run)' >&2; exit 1; }
  echo "Portable Node.js ready: $NODE_BIN" >&2
  unset _os _arch _plat _ext _dl _tools _tmp _ver
}
ensure_node
[ "$NODE_MAJOR" -ge 24 ] || { echo 'Node.js 24+ required' >&2; exit 1; }
USER_NAME="${NC_SERVICE_USER:-_nc}"
GROUP_NAME="${NC_SERVICE_GROUP:-$USER_NAME}"
# Faz A (user-space agent): NC_MODE=user runs the client as the operator login
# user under `systemd --user` + linger instead of the dedicated `_nc` system
# account. Default `system` keeps the proven layout byte-identical.
# Per-user installs (non-root, or NC_USER_INSTALL=1) always run in user mode:
# the tree is operator-owned and needs no elevation at all.
MODE="${NC_MODE:-system}"
case "$MODE" in
  system|user) ;;
  *) echo "NC_MODE must be 'system' or 'user'" >&2; exit 1 ;;
esac
if [ "$USER_INSTALL" -eq 1 ]; then
  if [ "$NC_UPGRADE_MODE" -eq 1 ] && [ "${NC_SYSTEM_INSTALL:-0}" = "1" ] && [ "${NC_USER_INSTALL:-0}" != "1" ]; then
    :
  else
    MODE=user
  fi
fi
OPERATOR=''
OP_UID=''
if [ "$MODE" = user ]; then
  if [ "$(id -u)" -eq 0 ]; then
    OPERATOR="${NC_OPERATOR_USER:-${SUDO_USER:-}}"
    if [ -z "$OPERATOR" ]; then
      if [ "$NC_UPGRADE_MODE" -eq 1 ]; then
        echo 'NC upgrade: user-mode operator unknown, skipping ownership repair (never running usermod).'
      else
        echo 'user mode needs NC_OPERATOR_USER or a sudo-invoking login user' >&2; exit 1
      fi
    elif [ "$OPERATOR" = root ]; then
      if [ "$NC_UPGRADE_MODE" -eq 1 ]; then
        echo 'NC upgrade: user mode refuses the root account as operator, skipping ownership repair.' >&2
        OPERATOR=''
      else
        echo 'user mode refuses the root account as operator' >&2; exit 1
      fi
    elif ! id "$OPERATOR" >/dev/null 2>&1; then
      if [ "$NC_UPGRADE_MODE" -eq 1 ]; then
        echo "NC upgrade: operator user '$OPERATOR' does not exist, skipping ownership repair." >&2
        OPERATOR=''
      else
        echo "operator user '$OPERATOR' does not exist" >&2; exit 1
      fi
    else
      OP_UID="$(id -u "$OPERATOR")"
      OP_HOME="$(getent passwd "$OPERATOR" | cut -d: -f6)"
      if [ -n "$OP_HOME" ] && [ -d "$OP_HOME" ]; then
        USER_NAME="$OPERATOR"
        GROUP_NAME="$(id -gn "$OPERATOR")"
      elif [ "$NC_UPGRADE_MODE" -eq 1 ]; then
        echo "NC upgrade: operator user '$OPERATOR' has no home directory, skipping ownership repair." >&2
        OPERATOR=''
      else
        echo "operator user '$OPERATOR' has no home directory" >&2; exit 1
      fi
      unset OP_HOME
    fi
  else
    # Non-root user install: we ARE the operator; nothing to provision.
    OPERATOR="$(id -un)"
    if [ -n "${NC_OPERATOR_USER:-}" ] && [ "$NC_OPERATOR_USER" != "$OPERATOR" ]; then
      if [ "$NC_UPGRADE_MODE" -eq 1 ]; then
        echo "NC upgrade: operator mismatch (NC_OPERATOR_USER=${NC_OPERATOR_USER} vs $OPERATOR), using invoking user." >&2
      else
        echo 'non-root install runs as the invoking user' >&2; exit 1
      fi
    fi
    OP_UID="$(id -u)"
    USER_NAME="$OPERATOR"
    GROUP_NAME="$(id -gn)"
  fi
else
  if [ "$(id -u)" -ne 0 ]; then
    if [ "$NC_UPGRADE_MODE" -eq 1 ]; then
      :
    else
      echo 'system install needs root (or run without privileges for a user install)' >&2; exit 1
    fi
  fi
  if [ "$(id -u)" -eq 0 ]; then
    if ! getent group "$GROUP_NAME" >/dev/null; then groupadd --system "$GROUP_NAME"; fi
    if ! id "$USER_NAME" >/dev/null 2>&1; then
      useradd --system --gid "$GROUP_NAME" --home-dir "$ROOT" --shell /usr/sbin/nologin "$USER_NAME"
    fi
  fi
  if [ "$NC_UPGRADE_MODE" -eq 0 ]; then
    PRIMARY_GID="$(id -g "$USER_NAME")"
    EXPECTED_GID="$(getent group "$GROUP_NAME" | cut -d: -f3)"
    [ "$PRIMARY_GID" = "$EXPECTED_GID" ] || { echo "NC service account '$USER_NAME' primary group must be '$GROUP_NAME'." >&2; exit 1; }
    USER_SHELL="$(getent passwd "$USER_NAME" | cut -d: -f7)"
    case "$USER_SHELL" in
      /usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false) ;;
      *) echo "NC service account '$USER_NAME' must use a non-login shell." >&2; exit 1 ;;
    esac
    USER_GROUPS="$(id -nG "$USER_NAME" | xargs)"
    # Journal readability (log_read): the unprivileged service identity needs
    # the narrowest journal-read group. Only systemd-journal is permitted as a
    # supplementary group; adm is broader and stays forbidden.
    USER_REST="$(printf '%s\n' $USER_GROUPS | grep -v -x -e "$GROUP_NAME" -e systemd-journal || true)"
    [ -z "$USER_REST" ] || { echo "NC service account '$USER_NAME' must not belong to supplementary groups: $USER_GROUPS" >&2; exit 1; }
    unset PRIMARY_GID EXPECTED_GID USER_SHELL USER_GROUPS USER_REST
    # Idempotent journal grant (migration-safe): existing system installs gain
    # the group on upgrade/reinstall; the service restart at the end of this
    # script picks the new membership up. Missing group (non-systemd) warns.
    if getent group systemd-journal >/dev/null; then
      if ! id -nG "$USER_NAME" | tr ' ' '\n' | grep -x -q systemd-journal; then
        usermod -aG systemd-journal "$USER_NAME"
      fi
    else
      echo 'Warning: systemd-journal group missing; system journal reads may require privileged helper.' >&2
    fi
  fi
fi
# BEGIN NC-UPGRADE-HANDLER (single source for `install.sh --update` refresh).
# Idempotent only: journal grant, directory repairs and helper-unit refresh.
# Never touches client identity (nc-client.env, device key) or data content.
nc_upgrade_ensure_dir() {
  _u_d="$1"; _u_mode="$2"; _u_owner="$3"; _u_group="$4"
  if [ ! -d "$_u_d" ]; then
    if [ "$(id -u)" -eq 0 ] && [ -n "$_u_owner" ] && [ -n "$_u_group" ]; then
      install -d -m "$_u_mode" -o "$_u_owner" -g "$_u_group" "$_u_d" && echo "NC upgrade: created directory $_u_d (mode $_u_mode, owner $_u_owner:$_u_group)."
    else
      mkdir -p "$_u_d" 2>/dev/null || true
      chmod "$_u_mode" "$_u_d" 2>/dev/null || true
      echo "NC upgrade: created directory $_u_d (mode $_u_mode)."
    fi
    unset _u_d _u_mode _u_owner _u_group
    return 0
  fi
  _u_cur_mode="$(stat -c '%a' "$_u_d" 2>/dev/null || stat -f '%Lp' "$_u_d" 2>/dev/null || true)"
  _u_cur_owner="$(stat -c '%U:%G' "$_u_d" 2>/dev/null || stat -f '%Su:%Sg' "$_u_d" 2>/dev/null || true)"
  _u_want_owner="${_u_owner}:${_u_group}"
  _u_want_norm="$(printf '%s' "$_u_mode" | sed 's/^0*//')"
  _u_cur_norm="$(printf '%s' "$_u_cur_mode" | sed 's/^0*//')"
  if [ "$_u_cur_norm" = "$_u_want_norm" ] && { [ "$(id -u)" -ne 0 ] || [ -z "$_u_owner" ] || [ "$_u_cur_owner" = "$_u_want_owner" ]; }; then
    echo "NC upgrade: directory $_u_d already correct (skip)."
  else
    if [ "$(id -u)" -eq 0 ] && [ -n "$_u_owner" ] && [ -n "$_u_group" ]; then
      chown "$_u_want_owner" "$_u_d" 2>/dev/null || true
      chmod "$_u_mode" "$_u_d" 2>/dev/null || true
    else
      chmod "$_u_mode" "$_u_d" 2>/dev/null || true
    fi
    echo "NC upgrade: fixed ownership/permissions on $_u_d (was $_u_cur_owner/$_u_cur_mode, now $_u_want_owner/$_u_mode)."
  fi
  unset _u_d _u_mode _u_owner _u_group _u_cur_mode _u_cur_owner _u_want_owner _u_want_norm _u_cur_norm
}
if [ "$NC_UPGRADE_MODE" -eq 1 ]; then
  echo "NC upgrade: starting system-level refresh (ROOT=$ROOT, MODE=$MODE)..."
  if [ "$MODE" = user ]; then
    echo 'NC upgrade: user install detected, skipping usermod/systemd-journal (not applicable).'
  elif [ "$(id -u)" -ne 0 ]; then
    echo 'NC upgrade: system-level skipped (needs root).'
  else
    if getent group systemd-journal >/dev/null 2>&1; then
      if id -nG "$USER_NAME" 2>/dev/null | tr ' ' '\n' | grep -x -q systemd-journal; then
        echo "NC upgrade: user $USER_NAME already in systemd-journal (already, skip usermod)."
      else
        if usermod -aG systemd-journal "$USER_NAME"; then
          echo "NC upgrade: added $USER_NAME to systemd-journal via usermod -aG systemd-journal $USER_NAME"
        else
          echo "Warning: usermod -aG systemd-journal $USER_NAME failed" >&2
          echo 'NC upgrade: usermod attempt failed (see warning).'
        fi
      fi
    else
      echo 'Warning: systemd-journal group missing; system journal reads may require privileged helper.' >&2
      echo 'NC upgrade: systemd-journal group missing, skipped.'
    fi
  fi
  if [ "$MODE" = user ]; then
    if [ "$(id -u)" -eq 0 ] && [ -n "$OPERATOR" ]; then
      nc_upgrade_ensure_dir "$ROOT" 0750 "$USER_NAME" "$GROUP_NAME"
      for _u_dname in app config data logs releases backups tmp; do
        nc_upgrade_ensure_dir "$ROOT/$_u_dname" 0750 "$USER_NAME" "$GROUP_NAME"
      done
      unset _u_dname
      nc_upgrade_ensure_dir "$ROOT/data/workspace" 0700 "$USER_NAME" "$GROUP_NAME"
      if [ "$(id -u)" -eq 0 ]; then
        nc_upgrade_ensure_dir "$ROOT/libexec" 0755 root root
      else
        nc_upgrade_ensure_dir "$ROOT/libexec" 0755 "" ""
      fi
    elif [ "$(id -u)" -ne 0 ]; then
      nc_upgrade_ensure_dir "$ROOT" 0750 "$USER_NAME" "$GROUP_NAME"
      for _u_dname in app config data logs releases backups tmp; do
        nc_upgrade_ensure_dir "$ROOT/$_u_dname" 0750 "$USER_NAME" "$GROUP_NAME"
      done
      unset _u_dname
      nc_upgrade_ensure_dir "$ROOT/data/workspace" 0700 "$USER_NAME" "$GROUP_NAME"
      nc_upgrade_ensure_dir "$ROOT/libexec" 0755 "" ""
    else
      echo 'NC upgrade: user-mode operator unknown, ensuring directories without ownership change.'
      for _u_dname in "" logs app config data releases backups tmp; do
        if [ -z "$_u_dname" ]; then _u_path="$ROOT"; else _u_path="$ROOT/$_u_dname"; fi
        if [ ! -d "$_u_path" ]; then mkdir -p "$_u_path" 2>/dev/null || true; chmod 0750 "$_u_path" 2>/dev/null || true; echo "NC upgrade: created directory $_u_path (mode 0750)."; else echo "NC upgrade: directory $_u_path already correct (skip)."; fi
      done
      unset _u_dname _u_path
    fi
  else
    if [ "$(id -u)" -eq 0 ]; then
      nc_upgrade_ensure_dir "$ROOT" 0750 root "$GROUP_NAME"
      for _u_dname in app config data logs releases backups tmp; do
        nc_upgrade_ensure_dir "$ROOT/$_u_dname" 0750 "$USER_NAME" "$GROUP_NAME"
      done
      unset _u_dname
      nc_upgrade_ensure_dir "$ROOT/data/workspace" 0700 "$USER_NAME" "$GROUP_NAME"
      nc_upgrade_ensure_dir "$ROOT/libexec" 0755 root root
      if [ -f "$ROOT/config/nc-device-key.pem" ]; then
        _u_key_owner="$(stat -c '%U:%G' "$ROOT/config/nc-device-key.pem" 2>/dev/null || stat -f '%Su:%Sg' "$ROOT/config/nc-device-key.pem" 2>/dev/null || true)"
        _u_key_mode="$(stat -c '%a' "$ROOT/config/nc-device-key.pem" 2>/dev/null || stat -f '%Lp' "$ROOT/config/nc-device-key.pem" 2>/dev/null || true)"
        if [ "$_u_key_owner" = "$USER_NAME:$GROUP_NAME" ] && [ "$_u_key_mode" = "600" ]; then
          echo "NC upgrade: $ROOT/config/nc-device-key.pem already correct (skip)."
        else
          chown "$USER_NAME:$GROUP_NAME" "$ROOT/config/nc-device-key.pem" 2>/dev/null || true
          chmod 0600 "$ROOT/config/nc-device-key.pem" 2>/dev/null || true
          echo "NC upgrade: fixed ownership/permissions on $ROOT/config/nc-device-key.pem."
        fi
        unset _u_key_owner _u_key_mode
      fi
    else
      echo 'NC upgrade: system-level skipped (needs root).'
    fi
  fi
  _u_env_dst="$ROOT/config/nc-client.env"
  if [ "$MODE" = user ]; then
    echo 'NC upgrade: user mode, privileged helper skipped (system-domain ops unavailable).'
  elif [ "$(id -u)" -ne 0 ]; then
    echo 'NC upgrade: system-level skipped (needs root).'
  else
    _u_install_dir=""
    for _u_cand in "$SRC/install" "$ROOT/app/install" "$ROOT/install"; do
      if [ -f "$_u_cand/nc-privileged-helper-linux.socket.in" ] && [ -f "$_u_cand/nc-privileged-helper-linux.service.in" ] && [ -f "$_u_cand/nc-privileged-helper-tmpfiles.in" ]; then
        _u_install_dir="$_u_cand"
        break
      fi
    done
    if [ -z "$_u_install_dir" ]; then
      _u_install_dir="$SRC/install"
    fi
    _u_socket_in="$_u_install_dir/nc-privileged-helper-linux.socket.in"
    _u_service_in="$_u_install_dir/nc-privileged-helper-linux.service.in"
    _u_tmpfiles_in="$_u_install_dir/nc-privileged-helper-tmpfiles.in"
    if [ ! -f "$_u_socket_in" ] || [ ! -f "$_u_service_in" ] || [ ! -f "$_u_tmpfiles_in" ]; then
      echo 'NC upgrade: helper templates missing in release, skipping privileged-helper refresh.' >&2
    else
      _u_tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t nc-upgrade.XXXXXX)"
      sed "s#@NC_SERVICE_GROUP@#$GROUP_NAME#g" "$_u_socket_in" > "$_u_tmpdir/nc-privileged-helper.socket"
      if [ -f "$HELPER_SOCKET" ] && cmp -s "$_u_tmpdir/nc-privileged-helper.socket" "$HELPER_SOCKET"; then
        echo "NC upgrade: $HELPER_SOCKET already current (skip)."
      else
        if install -m 0644 -o root -g root "$_u_tmpdir/nc-privileged-helper.socket" "$HELPER_SOCKET"; then
          echo "NC upgrade: installed $HELPER_SOCKET (updated via install -m 0644 -o root)."
        else
          echo "Warning: cannot install $HELPER_SOCKET" >&2
        fi
      fi
      _u_node="${NODE_BIN:-}"
      if [ -z "$_u_node" ]; then _u_node="$(command -v node || true)"; fi
      if [ -z "$_u_node" ] && [ -x "$ROOT/tools/node/bin/node" ]; then _u_node="$ROOT/tools/node/bin/node"; fi
      if [ -n "$_u_node" ]; then
        sed "s#@NODE_BIN@#$_u_node#g" "$_u_service_in" > "$_u_tmpdir/nc-privileged-helper.service"
        if [ -f "$HELPER_SERVICE" ] && cmp -s "$_u_tmpdir/nc-privileged-helper.service" "$HELPER_SERVICE"; then
          echo "NC upgrade: $HELPER_SERVICE already current (skip)."
        else
          if install -m 0644 -o root -g root "$_u_tmpdir/nc-privileged-helper.service" "$HELPER_SERVICE"; then
            echo "NC upgrade: installed $HELPER_SERVICE (updated via install -m 0644 -o root)."
          else
            echo "Warning: cannot install $HELPER_SERVICE" >&2
          fi
        fi
      else
        echo 'NC upgrade: node runtime missing, skipping helper service refresh.' >&2
      fi
      sed "s#@NC_SERVICE_GROUP@#$GROUP_NAME#g" "$_u_tmpfiles_in" > "$_u_tmpdir/nc-privileged-helper.conf"
      if [ -f "$HELPER_TMPFILES" ] && cmp -s "$_u_tmpdir/nc-privileged-helper.conf" "$HELPER_TMPFILES"; then
        echo "NC upgrade: $HELPER_TMPFILES already current (skip)."
      else
        if install -m 0644 -o root -g root "$_u_tmpdir/nc-privileged-helper.conf" "$HELPER_TMPFILES"; then
          echo "NC upgrade: installed $HELPER_TMPFILES (updated via install -m 0644 -o root)."
        else
          echo "Warning: cannot install $HELPER_TMPFILES" >&2
        fi
      fi
      if [ -f "$_u_env_dst" ] && [ -f "$ROOT/config/nc-device-key.pem" ] && id "$USER_NAME" >/dev/null 2>&1; then
        _u_uid="$(id -u "$USER_NAME" 2>/dev/null || true)"
        _u_gid="$(id -g "$USER_NAME" 2>/dev/null || true)"
        _u_cid="$(awk -F= '$1=="NC_CLIENT_ID"{print substr($0,index($0,"=")+1);exit}' "$_u_env_dst" 2>/dev/null || true)"
        if [ -n "$_u_uid" ] && [ -n "$_u_gid" ] && [ -n "$_u_cid" ]; then
          printf '{"client_id":"%s","service_gid":%s,"service_uid":%s}\n' "$_u_cid" "$_u_gid" "$_u_uid" > "$_u_tmpdir/privileged-helper.json"
          if [ -f "$ROOT/config/privileged-helper.json" ] && cmp -s "$_u_tmpdir/privileged-helper.json" "$ROOT/config/privileged-helper.json"; then
            echo "NC upgrade: $ROOT/config/privileged-helper.json already current (skip)."
          else
            if install -m 0600 -o root -g root "$_u_tmpdir/privileged-helper.json" "$ROOT/config/privileged-helper.json"; then
              echo "NC upgrade: installed $ROOT/config/privileged-helper.json (updated)."
            else
              echo "Warning: cannot install $ROOT/config/privileged-helper.json" >&2
            fi
          fi
        else
          echo 'NC upgrade: helper identity incomplete, skipping privileged-helper.json.'
        fi
        unset _u_uid _u_gid _u_cid
      else
        echo 'NC upgrade: helper identity files missing, skipping privileged-helper.json.'
      fi
      rm -rf "$_u_tmpdir"
      unset _u_tmpdir _u_node
      if command -v systemd-tmpfiles >/dev/null 2>&1 && [ -f "$HELPER_TMPFILES" ]; then
        systemd-tmpfiles --create "$HELPER_TMPFILES" 2>/dev/null || true
      fi
      if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
        systemctl stop nc-privileged-helper.service >/dev/null 2>&1 || true
      fi
    fi
    unset _u_socket_in _u_service_in _u_tmpfiles_in _u_install_dir _u_cand
  fi
  # Refresh the persistent upgrade helper from a fresh package copy (atomic
  # temp + mv: never truncate the running script in place). When invoked
  # from the persistent copy itself there is no fresher source, so skip.
  _u_persist_src="$SRC/install/install-linux.sh"
  if [ -f "$_u_persist_src" ]; then
    for _u_persist_dst in "$ROOT/install-linux.sh" "$ROOT/app/install/install-linux.sh"; do
      if [ -f "$_u_persist_dst" ] && cmp -s "$_u_persist_src" "$_u_persist_dst"; then
        echo "NC upgrade: $_u_persist_dst already current (skip)."
      elif [ "$_u_persist_src" -ef "$_u_persist_dst" ] 2>/dev/null; then
        echo "NC upgrade: $_u_persist_dst already current (skip)."
      else
        _u_persist_tmp="$ROOT/tmp/.install-linux.sh.$$"
        mkdir -p "$ROOT/tmp" "$(dirname "$_u_persist_dst")" 2>/dev/null || true
        if [ "$(id -u)" -eq 0 ]; then
          if install -m 0750 -o "$USER_NAME" -g "$GROUP_NAME" "$_u_persist_src" "$_u_persist_tmp" 2>/dev/null; then
            if mv -f "$_u_persist_tmp" "$_u_persist_dst" 2>/dev/null; then
              echo "NC upgrade: refreshed $_u_persist_dst (persistent helper)."
            fi
          fi
        else
          if install -m 0750 "$_u_persist_src" "$_u_persist_tmp" 2>/dev/null; then
            if mv -f "$_u_persist_tmp" "$_u_persist_dst" 2>/dev/null; then
              echo "NC upgrade: refreshed $_u_persist_dst (persistent helper)."
            fi
          fi
        fi
        rm -f "$_u_persist_tmp" 2>/dev/null || true
      fi
    done
    unset _u_persist_dst _u_persist_tmp
  fi
  unset _u_persist_src
  unset _u_env_dst
  echo 'NC upgrade: system-level refresh complete.'
  exit 0
fi
# END NC-UPGRADE-HANDLER
if [ "$MODE" = user ]; then
  # Migration: an older system unit would fight the user unit for the lock.
  if [ "$(id -u)" -eq 0 ]; then systemctl disable --now nc-client.service 2>/dev/null || true; fi
else
  systemctl stop nc-client.service 2>/dev/null || true
fi
# Install phase timing (SYN-INST-001): append-only breakdown for real
# install-cost data. Never fails the install.
TIMING_LOG="$ROOT/logs/install-timing.log"
_phase_t0=$SECONDS
phase_done(){
  _name="$1"
  _dt=$((SECONDS - _phase_t0))
  _phase_t0=$SECONDS
  { printf '%s phase=%s seconds=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_name" "$_dt" >> "$TIMING_LOG"; } 2>/dev/null || true
}
install -d -m 0750 -o "$USER_NAME" -g "$GROUP_NAME" "$ROOT/logs"
phase_done preflight-users-dirs
if [ "$(id -u)" -eq 0 ]; then
  if [ "$MODE" = user ]; then
    chown "$USER_NAME:$GROUP_NAME" "$ROOT"
  else
    chown root:"$GROUP_NAME" "$ROOT"
  fi
  chmod 0750 "$ROOT"
else
  chmod 0750 "$ROOT"
fi
_retired_root="/$(printf work)$(printf space)"
_nc_pids=''
for _proc in /proc/[0-9]*; do
  [ -r "$_proc/cmdline" ] || continue
  _cmd="$(tr '\000' ' ' < "$_proc/cmdline" 2>/dev/null || true)"
  case "$_cmd" in
    *"$ROOT/app/launcher.mjs"*|*"$ROOT/app/client.mjs"*)
      _pid="${_proc##*/}"
      [ "$_pid" = "$$" ] || _nc_pids="$_nc_pids $_pid"
      ;;
  esac
done
for _pid in $_nc_pids; do kill -TERM "$_pid" 2>/dev/null || true; done
for _wait in 1 2 3 4 5 6 7 8 9 10; do
  _alive=''
  for _pid in $_nc_pids; do kill -0 "$_pid" 2>/dev/null && _alive="$_alive $_pid" || true; done
  [ -z "$_alive" ] && break
  sleep 0.25
done
for _pid in $_alive; do kill -KILL "$_pid" 2>/dev/null || true; done
rm -f "$ROOT/data/client.lock"
unset _retired_root _nc_pids _alive _pid _proc _cmd _wait
for d in app config data logs releases backups tmp; do
  install -d -m 0750 -o "$USER_NAME" -g "$GROUP_NAME" "$ROOT/$d"
done
# Canonical writable workspace for file mutation tools (service-owned).
install -d -m 0700 -o "$USER_NAME" -g "$GROUP_NAME" "$ROOT/data/workspace"
if [ "$(id -u)" -eq 0 ]; then
  install -d -m 0755 -o root -g root "$ROOT/libexec"
else
  install -d -m 0755 "$ROOT/libexec"
fi
if [ -f "$ROOT/config/nc-device-key.pem" ]; then
  chown "$USER_NAME:$GROUP_NAME" "$ROOT/config/nc-device-key.pem"
  chmod 0600 "$ROOT/config/nc-device-key.pem"
fi
RUNTIME=(launcher.mjs singleton.mjs tar-extract.mjs uninstall-ops.mjs gui-launch.mjs browser-adapter.mjs browser-manager.mjs browser-jobs.mjs browser-runtime.mjs egress-policy.mjs client.mjs ws-transport.mjs agent-state.mjs shell-runner.mjs shell-ops.mjs session-reconnect.mjs ws-client.mjs structured-ops.mjs doc-extract.mjs mutation-ops.mjs path-auth.mjs sensitive-paths.mjs process-sessions.mjs service-ops.mjs diagnostics-ops.mjs system-log-ops.mjs package-ops.mjs git-ops.mjs project-ops.mjs container-ops.mjs log-ops.mjs host-policy.mjs consolidated-tools.mjs device-proof.mjs lifecycle.mjs updater.mjs nc-paths.mjs privileged-helper-contract.mjs privileged-helper-core.mjs privileged-helper-ipc.mjs linux-peer-credentials.mjs privileged-helper-linux-daemon.mjs privileged-helper-linux-operations.mjs privileged-helper-bootstrap.mjs privileged-helper-client.mjs privileged-helper-spawn.mjs privileged-helper-linux-readiness.mjs privileged-helper-provision.mjs privileged-helper-transport-proof.mjs privileged-helper-windows-service.mjs privileged-helper-windows-operations.mjs privileged-helper-windows-config.mjs privileged-helper-windows-readiness.mjs privileged-helper-darwin-daemon.mjs privileged-helper-darwin-operations.mjs privileged-helper-darwin-readiness.mjs darwin-peer-credentials.mjs package.json install/nc-privileged-helper-linux.socket.in install/nc-privileged-helper-linux.service.in install/nc-privileged-helper-tmpfiles.in install/install-linux.sh)
NEW="$ROOT/tmp/app-new-$STAMP"
install -d -m 0750 -o "$USER_NAME" -g "$GROUP_NAME" "$NEW"
for f in "${RUNTIME[@]}"; do
  [ -f "$SRC/$f" ] || { echo "missing runtime file: $f" >&2; exit 1; }
  mkdir -p "$NEW/$(dirname "$f")"
  case "$f" in
    *.sh) install -m 0750 -o "$USER_NAME" -g "$GROUP_NAME" "$SRC/$f" "$NEW/$f" ;;
    *) install -m 0640 -o "$USER_NAME" -g "$GROUP_NAME" "$SRC/$f" "$NEW/$f" ;;
  esac
done
# NOTE: install/install-linux.sh now rides RUNTIME (parity with
# RUNTIME_FILES) so the loop above stages it; the *.sh case keeps it
# executable. The former separate $NEW copy step was removed as redundant.
"$NODE_BIN" --check "$NEW/launcher.mjs"
"$NODE_BIN" --check "$NEW/client.mjs"
"$NODE_BIN" --check "$NEW/updater.mjs"
if [ -n "$(find "$ROOT/app" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
  mv "$ROOT/app" "$ROOT/backups/migration-app-$STAMP"
else
  rmdir "$ROOT/app" 2>/dev/null || true
fi
mv "$NEW" "$ROOT/app"
chown -R "$USER_NAME:$GROUP_NAME" "$ROOT/app"
phase_done runtime-copy

# Provision the optional Linux privileged-helper peer-credential broker.
# Base-agent installation must not depend on a compiler. If the helper cannot be
# built, it is disabled fail-closed and privileged_shell_exec is not advertised.
HELPER_READY=0
CC_BIN="$(command -v cc || command -v gcc || command -v clang || true)"
PEERCRED_SRC="$SRC/native/linux-peercred.c"
PEERCRED_TMP="$ROOT/tmp/nc-linux-peercred-$STAMP"
if [ "$(id -u)" != "0" ]; then
  # User mode needs no privilege broker: the operator owns the tree and the
  # user manager restarts the agent unprivileged. System-domain service ops
  # stay unavailable by design; a stale system helper from a previous system
  # install is left in place (only a root system install may remove it).
  echo 'User mode: privileged helper skipped (system-domain ops unavailable).' >&2
elif [ -n "$CC_BIN" ] && [ -f "$PEERCRED_SRC" ]; then
  if "$CC_BIN" -O2 -Wall -Wextra -Werror -o "$PEERCRED_TMP" "$PEERCRED_SRC"; then
    install -m 0755 -o root -g root "$PEERCRED_TMP" "$ROOT/libexec/nc-linux-peercred"
    HELPER_READY=1
  else
    echo 'Warning: NC privileged helper peer-credential broker build failed; helper disabled.' >&2
  fi
else
  echo 'Warning: no C compiler or peer-credential source; NC privileged helper disabled.' >&2
fi
rm -f "$PEERCRED_TMP"
phase_done helper-build

# Provision managed browser OS dependencies (Playwright + NC-managed Chromium
# converge post-boot from upstream: playwright-core via the npm registry,
# Chromium via the Playwright CDN — our hub never carries them).
# OS dependencies install only here at install time (never during OTA);
# the client health gate hides browser tools until convergence completes.
BROWSER_READY=0
if [ "$(id -u)" = "0" ]; then
  PIN_VERSION="$("$NODE_BIN" -e "import('file://$ROOT/app/browser-runtime.mjs').then((m) => console.log(m.BROWSER_RUNTIME_PIN.playwright))" 2>/dev/null || true)"
  if [ -n "$PIN_VERSION" ]; then
    install -d -m 0700 -o "$USER_NAME" -g "$GROUP_NAME" "$ROOT/data/browser"
    NPX_BIN="$(dirname "$NODE_BIN")/npx"
    if [ -x "$NPX_BIN" ] && PLAYWRIGHT_BROWSERS_PATH="$ROOT/data/browser/playwright-browsers" "$NPX_BIN" -y "playwright-core@$PIN_VERSION" install-deps chromium >/dev/null 2>&1; then
      echo 'Browser OS dependencies installed; runtime converges post-boot.' >&2
    else
      echo 'Warning: browser OS-dependency install skipped/failed; convergence may lack system libraries.' >&2
    fi
  else
    echo 'Warning: browser runtime pin unreadable; skipping OS-dependency install.' >&2
  fi
else
  echo 'Warning: non-root install; browser OS dependencies unavailable, convergence may lack system libraries.' >&2
fi
phase_done browser-install

ENV_DST="$ROOT/config/nc-client.env"
ENV_SRC=''
for p in "$ENV_DST" "$SRC/client.env" /etc/nc/nc-client.env; do
  if [ -f "$p" ]; then ENV_SRC="$p"; break; fi
done
if [ -n "$ENV_SRC" ] && [ "$ENV_SRC" != "$ENV_DST" ]; then
  awk '!/^(NC_ROOT|NC_AUDIT_FILE|NC_SERVER_LOG_FILE|NC_TUNNEL_LOG_FILE|NC_STATE_FILE|NC_CLIENT_LOG|NC_LOCAL_AUDIT_FILE)=/' "$ENV_SRC" > "$ROOT/tmp/nc-client.env"
  install -m 0640 -o "$USER_NAME" -g "$GROUP_NAME" "$ROOT/tmp/nc-client.env" "$ENV_DST"
  rm -f "$ROOT/tmp/nc-client.env"
elif [ ! -f "$ENV_DST" ]; then
  install -m 0640 -o "$USER_NAME" -g "$GROUP_NAME" /dev/null "$ENV_DST"
fi

migrate_one(){
  local dst="$1"; shift
  [ -e "$dst" ] && return 0
  local src
  for src in "$@"; do
    if [ -f "$src" ]; then
      install -m 0640 -o "$USER_NAME" -g "$GROUP_NAME" "$src" "$dst"
      return 0
    fi
  done
}
migrate_one "$ROOT/data/client-state.json" "$SRC/state.json"
migrate_one "$ROOT/logs/client.log" "$SRC/client.log"
migrate_one "$ROOT/logs/audit.jsonl" "$SRC/audit.jsonl"
chown -R "$USER_NAME:$GROUP_NAME" "$ROOT/config" "$ROOT/data" "$ROOT/logs" "$ROOT/releases" "$ROOT/backups" "$ROOT/tmp"
HELPER_SOCKET="${NC_HELPER_SOCKET:-/etc/systemd/system/nc-privileged-helper.socket}"
HELPER_SERVICE="${NC_HELPER_SERVICE:-/etc/systemd/system/nc-privileged-helper.service}"
HELPER_TMPFILES="${NC_HELPER_TMPFILES:-/etc/tmpfiles.d/nc-privileged-helper.conf}"
if [ "$HELPER_READY" -eq 1 ]; then
  PUBLIC_KEY="$ROOT/config/privileged-helper-public.pem"
  "$NODE_BIN" "$SRC/privileged-helper-bootstrap.mjs" "$ENV_DST" "$ROOT/config/nc-device-key.pem" "$PUBLIC_KEY" >/dev/null
  chown root:root "$PUBLIC_KEY"
  chmod 0644 "$PUBLIC_KEY"
  SERVICE_UID="$(id -u "$USER_NAME")"
  SERVICE_GID="$(id -g "$USER_NAME")"
  CLIENT_ID_VALUE="$(awk -F= '$1=="NC_CLIENT_ID"{print substr($0,index($0,"=")+1);exit}' "$ENV_DST")"
  printf '{"client_id":"%s","service_gid":%s,"service_uid":%s}\n' "$CLIENT_ID_VALUE" "$SERVICE_GID" "$SERVICE_UID" > "$ROOT/tmp/privileged-helper.json"
  install -m 0600 -o root -g root "$ROOT/tmp/privileged-helper.json" "$ROOT/config/privileged-helper.json"
  rm -f "$ROOT/tmp/privileged-helper.json"
  sed "s#@NC_SERVICE_GROUP@#$GROUP_NAME#g" "$SRC/install/nc-privileged-helper-linux.socket.in" > "$ROOT/tmp/nc-privileged-helper.socket"
  install -m 0644 -o root -g root "$ROOT/tmp/nc-privileged-helper.socket" "$HELPER_SOCKET"
  rm -f "$ROOT/tmp/nc-privileged-helper.socket"
  sed "s#@NODE_BIN@#$NODE_BIN#g" "$SRC/install/nc-privileged-helper-linux.service.in" > "$ROOT/tmp/nc-privileged-helper.service"
  install -m 0644 -o root -g root "$ROOT/tmp/nc-privileged-helper.service" "$HELPER_SERVICE"
  rm -f "$ROOT/tmp/nc-privileged-helper.service"
  sed "s#@NC_SERVICE_GROUP@#$GROUP_NAME#g" "$SRC/install/nc-privileged-helper-tmpfiles.in" > "$ROOT/tmp/nc-privileged-helper.conf"
  install -m 0644 -o root -g root "$ROOT/tmp/nc-privileged-helper.conf" "$HELPER_TMPFILES"
  rm -f "$ROOT/tmp/nc-privileged-helper.conf"
  systemd-tmpfiles --create "$HELPER_TMPFILES"
  # A running daemon holds the install-time identity in memory; stop it so the
  # next socket-activated spawn reloads the freshly written config. No-op on
  # fresh installs where the service is not running yet.
  systemctl stop nc-privileged-helper.service >/dev/null 2>&1 || true
else
  # User installs never own system-domain helper units: a previous system
  # install may have left units behind, but only a root system install may
  # remove them. The user-tree peer-credential binary is always safe to drop.
  rm -f "$ROOT/libexec/nc-linux-peercred"
  if [ "$MODE" = user ] || [ "$(id -u)" -ne 0 ]; then
    if [ -e "$HELPER_SOCKET" ] || [ -e "$HELPER_SERVICE" ] || [ -e "$HELPER_TMPFILES" ]; then
      echo "Warning: stale system helper left in place (needs root): $HELPER_SOCKET $HELPER_SERVICE $HELPER_TMPFILES" >&2
    fi
  else
    systemctl disable --now nc-privileged-helper.socket nc-privileged-helper.service >/dev/null 2>&1 || true
    rm -f "$HELPER_SOCKET" "$HELPER_SERVICE" "$HELPER_TMPFILES"
  fi
fi
if [ "$MODE" = user ]; then
  # Stamp the runtime mode so service-ops routes self-management to
  # `systemctl --user` without the helper.
  if ! grep -q '^NC_SERVICE_MODE=' "$ENV_DST" 2>/dev/null; then
    printf 'NC_SERVICE_MODE=user\nNC_SERVICE_UNIT=nc-client\nNC_OPERATOR_USER=%s\n' "$OPERATOR" >> "$ENV_DST"
  fi
  chown "$USER_NAME:$GROUP_NAME" "$ENV_DST"
fi
if [ "$MODE" = user ]; then
  OP_HOME_DIR="$(getent passwd "$OPERATOR" | cut -d: -f6)"
  [ -n "$OP_HOME_DIR" ] || OP_HOME_DIR="$HOME"
  USER_UNIT_DIR="$OP_HOME_DIR/.config/systemd/user"
  USER_UNIT="$USER_UNIT_DIR/nc-client.service"
  install -d -m 0755 -o "$OPERATOR" -g "$GROUP_NAME" "$USER_UNIT_DIR"
  cat > "$ROOT/tmp/nc-client-user.service" <<EOF
[Unit]
Description=NC Client (user)
After=network-online.target
Wants=network-online.target
ConditionPathExists=!$ROOT/data/retired.json

[Service]
Type=simple
WorkingDirectory=$ROOT/app
ExecStart=$NODE_BIN $ROOT/app/launcher.mjs
Restart=always
RestartSec=5
SuccessExitStatus=75
RestartPreventExitStatus=75
TimeoutStopSec=10
UMask=0027
NoNewPrivileges=true

[Install]
WantedBy=default.target
EOF
  install -m 0644 -o "$OPERATOR" -g "$GROUP_NAME" "$ROOT/tmp/nc-client-user.service" "$USER_UNIT"
  rm -f "$ROOT/tmp/nc-client-user.service"
  # Retire any previous system unit so the two managers never fight.
  if [ "$(id -u)" -eq 0 ]; then
    systemctl disable --now nc-client.service >/dev/null 2>&1 || true
    rm -f "$UNIT"
    systemctl daemon-reload
  fi
  unset OP_HOME_DIR USER_UNIT_DIR
else
  cat > "$UNIT" <<EOF
[Unit]
Description=NC Client
After=network-online.target
Wants=network-online.target
ConditionPathExists=!$ROOT/data/retired.json

[Service]
Type=simple
User=$USER_NAME
Group=$GROUP_NAME
WorkingDirectory=$ROOT/app
ExecStart=$NODE_BIN $ROOT/app/launcher.mjs
Restart=always
RestartSec=5
SuccessExitStatus=75
RestartPreventExitStatus=75
TimeoutStopSec=10
UMask=0027
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
fi
# Run a user-manager command as the operator: directly when we are the
# operator, via runuser when root installed on their behalf.
_ucmd(){
  if [ "$(id -u)" -eq 0 ]; then
    runuser -u "$OPERATOR" -- env XDG_RUNTIME_DIR="/run/user/$OP_UID" "$@"
  else
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$OP_UID}" "$@"
  fi
}
_user_bus_ok(){
  _ucmd systemctl --user show-environment >/dev/null 2>&1
}
if [ "$MODE" = user ]; then
  chmod 0644 "$USER_UNIT"
  if [ "$(id -u)" -eq 0 ]; then
    loginctl enable-linger "$OPERATOR" 2>/dev/null || echo 'Warning: linger not enabled; agent stops at logout without it.' >&2
    # The user manager may not be running yet (fresh linger): start it now so
    # `systemctl --user` below can reach the bus.
    systemctl start "user@$OP_UID.service" >/dev/null 2>&1 || true
    for _w in 1 2 3 4 5 6 7 8 9 10; do
      [ -d "/run/user/$OP_UID" ] && break
      sleep 0.5
    done
    unset _w
  else
    loginctl enable-linger "$OPERATOR" >/dev/null 2>&1 || echo "Warning: linger needs root (sudo loginctl enable-linger $OPERATOR); agent stops at logout without it." >&2
  fi
  if _user_bus_ok; then
    _ucmd systemctl --user daemon-reload
  fi
else
  chmod 0644 "$UNIT"
  systemctl daemon-reload
fi
# Remove the obsolete pre-centralization local MCP unit only when it still points at the retired NC source tree.
if [ "$(id -u)" -eq 0 ]; then
_retired_root="/$(printf work)$(printf space)"
_legacy_mcp_unit=/etc/systemd/system/nc-mcp.service
if [ -f "$_legacy_mcp_unit" ] && grep -Fq "$_retired_root/nc-mcp" "$_legacy_mcp_unit"; then
  systemctl disable --now nc-mcp.service >/dev/null 2>&1 || true
  rm -f "$_legacy_mcp_unit"
  systemctl daemon-reload
fi
unset _retired_root _legacy_mcp_unit
fi
rm -f "$ROOT/data/retired.json"
if [ "$(id -u)" -eq 0 ]; then
  install -m 0700 -o root -g root "$SRC/install/uninstall-linux.sh" "$ROOT/uninstall.sh"
else
  install -m 0700 "$SRC/install/uninstall-linux.sh" "$ROOT/uninstall.sh"
fi
# Persistent upgrade helper for `install.sh --update` up-to-date path
# (same pattern as uninstall.sh above). Staged via temp + atomic mv so a
# running script is never truncated in place; bash keeps reading the old
# inode after mv. Skip when source and destination are the same file.
_nc_helper_src=""
if [ -f "$SRC/install/install-linux.sh" ]; then
  _nc_helper_src="$SRC/install/install-linux.sh"
elif [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  _nc_helper_src="${BASH_SOURCE[0]}"
else
  _nc_helper_src="$0"
fi
if [ -f "$_nc_helper_src" ]; then
  _nc_helper_tmp="$ROOT/tmp/.install-linux.sh.$STAMP"
  if [ "$_nc_helper_src" -ef "$ROOT/install-linux.sh" ] 2>/dev/null; then
    :
  elif [ "$(id -u)" -eq 0 ]; then
    if install -m 0750 -o "$USER_NAME" -g "$GROUP_NAME" "$_nc_helper_src" "$_nc_helper_tmp" 2>/dev/null; then
      mv -f "$_nc_helper_tmp" "$ROOT/install-linux.sh" 2>/dev/null || true
    fi
  else
    if install -m 0750 "$_nc_helper_src" "$_nc_helper_tmp" 2>/dev/null; then
      mv -f "$_nc_helper_tmp" "$ROOT/install-linux.sh" 2>/dev/null || true
    fi
  fi
  rm -f "$_nc_helper_tmp" 2>/dev/null || true
fi
unset _nc_helper_src _nc_helper_tmp
if [ "$MODE" = user ]; then
  # Offline-safe enable: symlink first (works without a bus), then the
  # manager calls when reachable. Without a bus the agent starts at next login.
  _want_dir="$(dirname "$USER_UNIT")/default.target.wants"
  if [ "$(id -u)" -eq 0 ]; then
    install -d -m 0755 -o "$OPERATOR" -g "$GROUP_NAME" "$_want_dir"
  else
    mkdir -p "$_want_dir"
  fi
  ln -sfn ../nc-client.service "$_want_dir/nc-client.service"
  unset _want_dir
  if [ "$HELPER_READY" -eq 1 ]; then
    systemctl enable --now nc-privileged-helper.socket
  fi
  if _user_bus_ok; then
    _ucmd systemctl --user enable nc-client.service
    _ucmd systemctl --user restart nc-client.service
    sleep 2
    _ucmd systemctl --user is-active --quiet nc-client.service
  else
    echo 'Warning: user bus unreachable; unit installed and enabled, agent starts at next login.' >&2
    echo "To start now: XDG_RUNTIME_DIR=/run/user/$OP_UID systemctl --user start nc-client.service" >&2
  fi
else
  systemctl enable nc-client.service
  if [ "$HELPER_READY" -eq 1 ]; then
    systemctl enable --now nc-privileged-helper.socket
  fi
  systemctl restart nc-client.service
  sleep 2
  systemctl is-active --quiet nc-client.service
fi
phase_done service-activate
# Retention hygiene (SYN-INST-001): release/download caches and migration
# backups grow unboundedly (~3 MB per agent version + full app copies).
# Rollback needs only the previous generation: keep newest 3 releases and
# newest 2 migration backups; never touch the live app tree or client DB.
prune_oldest() {
  _dir="$1"; _keep="$2"; _pat="$3"
  [ -d "$_dir" ] || return 0
  # GNU find (Linux installer). Scoped names are version/timestamp dirs
  # without spaces. _pat is an ERE fragment matched against the basename
  # (no ^ anchor: find -regex must match the whole path).
  find "$_dir" -maxdepth 1 -mindepth 1 -regextype posix-extended -regex ".*/($_pat)" -printf '%T@ %p\n' 2>/dev/null |
    sort -rn |
    tail -n +"$((_keep + 1))" |
    cut -d' ' -f2- |
    while IFS= read -r _v; do
      [ -n "$_v" ] && rm -rf "$_v"
    done
  unset _dir _keep _pat _v
}
prune_oldest "$ROOT/releases/client" 3 '[0-9]+\.[0-9]+\.[0-9]+$'
prune_oldest "$ROOT/backups/client" 2 'previous-.*'
prune_oldest "$ROOT/backups" 2 'migration-app-.*'
phase_done retention-prune
if [ "$BROWSER_READY" -eq 1 ]; then
  printf 'NC canonical install complete: %s (managed browser runtime ready)\n' "$ROOT"
else
  printf 'NC canonical install complete: %s (managed browser runtime NOT ready; browser tools hidden until installed)\n' "$ROOT"
fi
