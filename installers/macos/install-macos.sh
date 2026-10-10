#!/bin/bash
set -euo pipefail
# Never die silently under errexit: any failing critical step reports its line.
trap 'echo "NC macOS install failed at line $LINENO (exit $?)" >&2' ERR
ROOT="${NC_ROOT:-/opt/nc}"
PLIST=/Library/LaunchDaemons/com.nc.client.plist
SRC="${NC_SRC:-$(cd "$(dirname "$0")/.." && pwd)}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
# Privilege model: root installs target the machine tree; anything else is a
# per-user install into the operator's own tree with zero elevation.
# NC_USER_INSTALL=1 forces the user path explicitly.
USER_INSTALL=0
if [ "$(id -u)" -ne 0 ]; then USER_INSTALL=1; fi
if [ "${NC_USER_INSTALL:-0}" = "1" ]; then USER_INSTALL=1; fi
if [ "$(id -u)" -ne 0 ] && [ "${NC_SYSTEM_INSTALL:-0}" = "1" ]; then
  echo 'root required for system install' >&2; exit 1
fi
if [ "$USER_INSTALL" -eq 1 ] && [ -z "${NC_ROOT:-}" ]; then
  [ -n "${HOME:-}" ] && [ -d "$HOME" ] || { echo 'user install needs a home directory' >&2; exit 1; }
  ROOT="$HOME/Library/Application Support/nc"
fi
# Node.js 24+: system runtime when present, otherwise a portable runtime
# fetched from upstream nodejs.org into the install tree (the hub never
# carries runtimes).
ensure_node(){
  NODE_BIN="${NC_NODE_BIN:-$(command -v node || true)}"
  if [ -z "$NODE_BIN" ] && [ -x "$ROOT/tools/node/bin/node" ]; then NODE_BIN="$ROOT/tools/node/bin/node"; fi
  if [ -n "$NODE_BIN" ]; then
    NODE_MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
    case "$NODE_MAJOR" in ''|*[!0-9]*) NODE_MAJOR=0 ;; esac
    if [ "$NODE_MAJOR" -ge 24 ] 2>/dev/null; then return 0; fi
  fi
  _arch="$(uname -m)"
  case "$_arch" in
    x86_64) _plat=darwin-x64 ;;
    arm64) _plat=darwin-arm64 ;;
    *) echo "Node.js 24+ required (no portable build for $_arch)" >&2; exit 1 ;;
  esac
  command -v curl >/dev/null 2>&1 || { echo 'Node.js 24+ required (no curl for portable bootstrap)' >&2; exit 1; }
  echo 'Node.js 24+ not found; fetching portable runtime from nodejs.org...' >&2
  if command -v python3 >/dev/null 2>&1; then
    _ver="$(curl -fsSL https://nodejs.org/dist/index.json 2>/dev/null | python3 -c 'import json,sys; print([e["version"] for e in json.load(sys.stdin) if e["version"].startswith("v24.") and e.get("lts")][0])' 2>/dev/null || true)"
  else
    _ver="$(curl -fsSL https://nodejs.org/dist/index.json 2>/dev/null | grep -o '"version":"v24[^"]*"' | head -n1 | cut -d'"' -f4 || true)"
  fi
  [ -n "$_ver" ] || { echo 'Node.js 24+ required (portable index unreadable)' >&2; exit 1; }
  _tools="$ROOT/tools/node"
  _tmp="$(mktemp -d)"
  curl -fsSL "https://nodejs.org/dist/$_ver/node-$_ver-$_plat.tar.gz" -o "$_tmp/node.tar.gz" || { echo 'Node.js 24+ required (portable download failed)' >&2; exit 1; }
  mkdir -p "$_tools"
  tar -xzf "$_tmp/node.tar.gz" -C "$_tools" --strip-components=1 || { echo 'Node.js 24+ required (portable extract failed)' >&2; exit 1; }
  rm -rf "$_tmp"
  NODE_BIN="$_tools/bin/node"
  export PATH="$_tools/bin:$PATH"
  NODE_MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [ "$NODE_MAJOR" -ge 24 ] 2>/dev/null || { echo 'Node.js 24+ required (portable runtime failed to run)' >&2; exit 1; }
  echo "Portable Node.js ready: $NODE_BIN" >&2
  unset _arch _plat _tools _tmp _ver
}
ensure_node
[ "$NODE_MAJOR" -ge 24 ] || { echo 'Node.js 24+ required' >&2; exit 1; }
USER_NAME="${NC_SERVICE_USER:-_nc}"
GROUP_NAME="${NC_SERVICE_GROUP:-$USER_NAME}"
# Faz A (user-space agent): NC_MODE=user runs the client as the operator login
# user under a per-user LaunchAgent instead of the `_nc` LaunchDaemon.
# Default `system` keeps the proven layout byte-identical.
MODE="${NC_MODE:-system}"
case "$MODE" in
  system|user) ;;
  *) echo "NC_MODE must be 'system' or 'user'" >&2; exit 1 ;;
esac
if [ "$USER_INSTALL" -eq 1 ]; then MODE=user; fi
OPERATOR=''
OP_UID=''
OP_HOME=''
if [ "$MODE" = user ]; then
  if [ "$(id -u)" -eq 0 ]; then
    OPERATOR="${NC_OPERATOR_USER:-${SUDO_USER:-}}"
    [ -z "$OPERATOR" ] && OPERATOR="$(stat -f %Su /dev/console 2>/dev/null || true)"
    [ -n "$OPERATOR" ] || { echo 'user mode needs NC_OPERATOR_USER, a sudo-invoking user, or a console login' >&2; exit 1; }
    [ "$OPERATOR" != root ] || { echo 'user mode refuses the root account as operator' >&2; exit 1; }
    dscl . -read "/Users/$OPERATOR" >/dev/null 2>&1 || { echo "operator user '$OPERATOR' does not exist" >&2; exit 1; }
    OP_UID="$(id -u "$OPERATOR")"
    OP_HOME="$(dscl . -read "/Users/$OPERATOR" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    [ -d "$OP_HOME" ] || { echo "operator user '$OPERATOR' has no home directory" >&2; exit 1; }
  else
    # Non-root user install: we ARE the operator; nothing to provision.
    OPERATOR="$(id -un)"
    if [ -n "${NC_OPERATOR_USER:-}" ] && [ "$NC_OPERATOR_USER" != "$OPERATOR" ]; then
      echo 'non-root install runs as the invoking user' >&2; exit 1
    fi
    OP_UID="$(id -u)"
    OP_HOME="$HOME"
  fi
  USER_NAME="$OPERATOR"
  GROUP_NAME="$(id -gn "$OPERATOR")"
  AGENT_PLIST="$OP_HOME/Library/LaunchAgents/com.nc.client.plist"
  # Migration: a previous system daemon would fight the agent for the lock.
  if [ "$(id -u)" -eq 0 ]; then launchctl bootout system "$PLIST" 2>/dev/null || true; fi
else
  [ "$(id -u)" -eq 0 ] || { echo 'system install needs root (or run without privileges for a user install)' >&2; exit 1; }
  if ! dscl . -read "/Groups/$GROUP_NAME" >/dev/null 2>&1; then
  [ "$GROUP_NAME" = "_nc" ] || { echo "Service group '$GROUP_NAME' does not exist." >&2; exit 1; }
  SERVICE_ID="$( (dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID) 2>/dev/null | awk '$2 ~ /^[0-9]+$/ && $2 >= 200 && $2 < 500 { used[$2]=1 } END { for (i=499; i>=200; i--) if (!used[i]) { print i; exit } }' )"
  [ -n "$SERVICE_ID" ] || { echo 'No free macOS service UID/GID available in 200-499.' >&2; exit 1; }
  dscl . -create "/Groups/$GROUP_NAME"
  dscl . -create "/Groups/$GROUP_NAME" PrimaryGroupID "$SERVICE_ID"
fi
fi
if [ "$MODE" = system ]; then
if ! dscl . -read "/Users/$USER_NAME" >/dev/null 2>&1; then
  [ "$USER_NAME" = "_nc" ] || { echo "Service account '$USER_NAME' does not exist." >&2; exit 1; }
  SERVICE_ID="$(dscl . -read "/Groups/$GROUP_NAME" PrimaryGroupID | awk '{print $2}')"
  dscl . -create "/Users/$USER_NAME"
  dscl . -create "/Users/$USER_NAME" UniqueID "$SERVICE_ID"
  dscl . -create "/Users/$USER_NAME" PrimaryGroupID "$SERVICE_ID"
  dscl . -create "/Users/$USER_NAME" NFSHomeDirectory /var/empty
  dscl . -create "/Users/$USER_NAME" UserShell /usr/bin/false
  dscl . -create "/Users/$USER_NAME" RealName 'NC Service'
  dscl . -create "/Users/$USER_NAME" IsHidden 1
  dscl . -create "/Users/$USER_NAME" Password '*'
fi
if dseditgroup -o checkmember -m "$USER_NAME" admin 2>/dev/null | grep -qi '^yes'; then
  echo "NC service account '$USER_NAME' must not be an administrator." >&2
  exit 1
fi
fi
unset SERVICE_ID
if [ "$(id -u)" -eq 0 ]; then launchctl bootout system "$PLIST" 2>/dev/null || true; fi
if [ "$MODE" = user ]; then
  mkdir -p "$ROOT"
  if [ "$(id -u)" -eq 0 ]; then chown "$USER_NAME:$GROUP_NAME" "$ROOT"; fi
else
  mkdir -p "$ROOT"
  chown root:"$GROUP_NAME" "$ROOT"
fi
chmod 0750 "$ROOT"
_retired_root="/$(printf work)$(printf space)"
_nc_pids=''
while IFS= read -r _line; do
  _pid="$(printf '%s\n' "$_line" | awk '{print $1}')"
  _cmd="$(printf '%s\n' "$_line" | cut -d' ' -f2-)"
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
rm -f "$ROOT/data/client.lock"
unset _retired_root _nc_pids _alive _pid _cmd _line _wait
for d in app config data logs releases backups tmp; do
  install -d -m 0750 -o "$USER_NAME" -g "$GROUP_NAME" "$ROOT/$d"
done
# Canonical writable workspace for file mutation tools (service-owned).
install -d -m 0700 -o "$USER_NAME" -g "$GROUP_NAME" "$ROOT/data/workspace"
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
  install -m 0640 -o "$USER_NAME" -g "$GROUP_NAME" "$SRC/$f" "$NEW/$f"
done
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
ENV_DST="$ROOT/config/nc-client.env"
ENV_SRC=''
for p in "$ENV_DST" "$SRC/client.env" /usr/local/nc/client.env /opt/nc-client/client.env; do
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
migrate_one "$ROOT/data/client-state.json" "$SRC/state.json" /usr/local/nc/state.json /opt/nc-client/state.json
migrate_one "$ROOT/logs/client.log" "$SRC/client.log" /usr/local/nc/client.log /opt/nc-client/client.log
migrate_one "$ROOT/logs/audit.jsonl" "$SRC/audit.jsonl" /usr/local/nc/audit.jsonl /opt/nc-client/audit.jsonl
chown -R "$USER_NAME:$GROUP_NAME" "$ROOT/config" "$ROOT/data" "$ROOT/logs" "$ROOT/releases" "$ROOT/backups" "$ROOT/tmp"
# SYN-BRW-004: the service user (_nc → /var/empty) has no writable HOME and
# Chromium CHECK-traps (SIGILL) without one. Provision a managed 0700 home
# for browser child processes (code also falls back here at runtime via OTA).
install -d -m 0700 -o "$USER_NAME" -g "$GROUP_NAME" "$ROOT/data/browser/service-home"

# Managed browser runtime (Playwright + NC-managed Chromium) converges
# post-boot from upstream (npm registry + Playwright CDN); no payload is
# carried and no OS-dependency step exists on macOS. Browser tools stay
# hidden behind the health gate until convergence completes.
BROWSER_READY=0
echo 'Browser runtime converges post-boot; browser tools hidden until installed.' >&2
if [ "$MODE" = user ]; then
  # Stamp the runtime mode so service-ops routes self-management to the
  # operator's gui domain instead of the system daemon.
  if ! grep -q '^NC_SERVICE_MODE=' "$ENV_DST" 2>/dev/null; then
    printf 'NC_SERVICE_MODE=user\nNC_SERVICE_UNIT=com.nc.client\nNC_OPERATOR_USER=%s\n' "$OPERATOR" >> "$ENV_DST"
  fi
  chown "$USER_NAME:$GROUP_NAME" "$ENV_DST"
  install -d -m 0755 -o "$OPERATOR" -g "$GROUP_NAME" "$OP_HOME/Library/LaunchAgents"
  # SYN-BRW-004 (narrowed 2026-09-14): the managed service-home override is
  # only for unwritable operator homes (service users like _nc -> /var/empty,
  # where Chromium CHECK-traps). A healthy operator keeps the ambient HOME:
  # a blanket override poisons shell sessions, os.homedir() and user-folder
  # discovery for every normal user install.
  HOME_OVERRIDE=""
  OP_WRITABLE=0
  if [ "$(id -u)" -eq 0 ]; then
    if su -s /bin/sh "$OPERATOR" -c "test -w \"$OP_HOME\"" 2>/dev/null; then
      OP_WRITABLE=0
    else
      OP_WRITABLE=1
    fi
  else
    if test -w "$OP_HOME" 2>/dev/null; then
      OP_WRITABLE=0
    else
      OP_WRITABLE=1
    fi
  fi
  if [ "$OP_WRITABLE" -ne 0 ]; then
    HOME_OVERRIDE="<key>EnvironmentVariables</key><dict><key>HOME</key><string>$ROOT/data/browser/service-home</string></dict>"
  fi
  cat > "$ROOT/tmp/com.nc.client.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.nc.client</string>
<key>ProgramArguments</key><array><string>$NODE_BIN</string><string>$ROOT/app/launcher.mjs</string></array>
<key>WorkingDirectory</key><string>$ROOT/app</string>
$HOME_OVERRIDE
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ProcessType</key><string>Background</string>
</dict></plist>
EOF
  install -m 0644 -o "$OPERATOR" -g "$GROUP_NAME" "$ROOT/tmp/com.nc.client.plist" "$AGENT_PLIST"
  rm -f "$ROOT/tmp/com.nc.client.plist"
  plutil -lint "$AGENT_PLIST"
  # Retire any previous system daemon so the two managers never fight.
  launchctl bootout system/com.nc.client >/dev/null 2>&1 || true
  rm -f "$PLIST"
  rm -f /etc/sudoers.d/nc-uninstall
else
  # Same narrowing as the user branch: service users (_nc -> /var/empty) keep
  # the managed override, real users keep their ambient HOME.
  SVC_HOME_OVERRIDE=""
  if su -s /bin/sh "$USER_NAME" -c 'test -w "$HOME"' 2>/dev/null; then
    : # service home writable: keep ambient HOME
  else
    SVC_HOME_OVERRIDE="<key>EnvironmentVariables</key><dict><key>HOME</key><string>$ROOT/data/browser/service-home</string></dict>"
  fi
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.nc.client</string>
<key>ProgramArguments</key><array><string>$NODE_BIN</string><string>$ROOT/app/launcher.mjs</string></array>
<key>WorkingDirectory</key><string>$ROOT/app</string>
<key>UserName</key><string>$USER_NAME</string>
<key>GroupName</key><string>$GROUP_NAME</string>
$SVC_HOME_OVERRIDE
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ProcessType</key><string>Background</string>
</dict></plist>
EOF
fi
if [ "$MODE" = user ]; then
  chmod 0644 "$AGENT_PLIST"
  rm -f "$ROOT/data/retired.json"
  if [ "$(id -u)" -eq 0 ]; then
    install -m 0700 -o root -g wheel "$SRC/install/uninstall-macos.sh" "$ROOT/uninstall.sh"
  else
    install -m 0700 "$SRC/install/uninstall-macos.sh" "$ROOT/uninstall.sh"
  fi
  # User mode needs no sudoers rule: the operator owns the tree, so the
  # panel uninstall path works directly.
  launchctl bootout "gui/$OP_UID/com.nc.client" >/dev/null 2>&1 || true
  if [ "$(id -u)" -eq 0 ]; then
    launchctl bootstrap "gui/$OP_UID" "$AGENT_PLIST" >/dev/null 2>&1 || \
      sudo -u "$OPERATOR" launchctl bootstrap "gui/$OP_UID" "$AGENT_PLIST"
  else
    launchctl bootstrap "gui/$OP_UID" "$AGENT_PLIST" >/dev/null 2>&1 || \
      echo 'Warning: agent launch failed (no GUI session?); it starts at next login.' >&2
  fi
  launchctl enable "gui/$OP_UID/com.nc.client" >/dev/null 2>&1 || true
  sleep 2
  if [ "$(id -u)" -eq 0 ]; then
    launchctl print "gui/$OP_UID/com.nc.client" >/dev/null
  else
    launchctl print "gui/$OP_UID/com.nc.client" >/dev/null 2>&1 || echo 'Warning: agent not yet running; check at next login.' >&2
  fi
else
chmod 0644 "$PLIST"
plutil -lint "$PLIST"
rm -f "$ROOT/data/retired.json"
install -m 0700 -o root -g wheel "$SRC/install/uninstall-macos.sh" "$ROOT/uninstall.sh"
# On-demand root uninstall for panel-initiated removal: the agent runs as
# _nc and cannot touch the daemon or /opt/nc. This sudoers rule allows
# exactly one command (the installed uninstaller above, root-owned 0700)
# without a password. Validated with visudo; failure here only disables
# remote uninstall, never the install.
# The sudoers rule grants root NOPASSWD for one fixed path. A variable
# $ROOT here (overridable via NC_ROOT, default /opt/nc for system mode)
# would let a custom root widen that grant, so only write the rule for the
# canonical system layout; custom roots keep working, just without
# panel-initiated (passwordless) uninstall (fail closed).
if [ "$ROOT" != "/opt/nc" ]; then
  echo "Warning: custom ROOT ($ROOT) refuses the system sudoers uninstall rule; panel uninstall will fail closed." >&2
  rm -f /etc/sudoers.d/nc-uninstall
else
printf '%s\n' "$USER_NAME ALL=(root) NOPASSWD: /opt/nc/uninstall.sh" > /etc/sudoers.d/nc-uninstall
chmod 0440 /etc/sudoers.d/nc-uninstall
if visudo -c -f /etc/sudoers.d/nc-uninstall >/dev/null 2>&1; then
  echo 'On-demand uninstall rule installed (panel-initiated removal enabled).'
else
  echo 'Warning: sudoers validation failed; removing rule, panel uninstall will fail closed.' >&2
  rm -f /etc/sudoers.d/nc-uninstall
fi
fi
launchctl bootout system/com.nc.client >/dev/null 2>&1 || true
# A stale disabled record (left by a previous panel uninstall) wedges
# `bootstrap` with "Input/output error": clear it first. Enable-before-
# bootstrap is a harmless no-op on fresh hosts.
launchctl enable system/com.nc.client >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST"
launchctl enable system/com.nc.client
sleep 2
launchctl print system/com.nc.client >/dev/null
fi
# Faz 10: macOS privileged-helper daemon (root LaunchDaemon + LOCAL_PEERCRED
# peer check). System installs only: user installs run as the operator (no
# elevation to broker), so the helper stays unavailable there by design and
# the tool stays hidden. Needs a C compiler (Xcode CLT); otherwise disabled
# fail-closed.
HELPER_PLIST=/Library/LaunchDaemons/com.nc.privileged-helper.plist
if [ "$(id -u)" != "0" ]; then
  echo 'User mode: privileged helper skipped (system-domain ops unavailable).' >&2
  launchctl bootout system/com.nc.privileged-helper >/dev/null 2>&1 || true
  rm -f "$HELPER_PLIST" "$ROOT/libexec/nc-darwin-peercred"
else
HELPER_READY=0
HELPER_CC="$(command -v cc || command -v gcc || command -v clang || true)"
HELPER_SRC="$SRC/native/darwin-peercred.c"
HELPER_TMP="$ROOT/tmp/nc-darwin-peercred-$STAMP"
if [ -n "$HELPER_CC" ] && [ -f "$HELPER_SRC" ]; then
  if "$HELPER_CC" -O2 -Wall -Wextra -Werror -o "$HELPER_TMP" "$HELPER_SRC" 2>/dev/null; then
    install -d -m 0755 -o root -g wheel "$ROOT/libexec"
    install -m 0755 -o root -g wheel "$HELPER_TMP" "$ROOT/libexec/nc-darwin-peercred"
    HELPER_READY=1
  else
    echo 'Warning: privileged helper peer-credential build failed; helper disabled.' >&2
  fi
else
  echo 'Warning: no C compiler or peer-credential source; NC privileged helper disabled.' >&2
fi
rm -f "$HELPER_TMP"
if [ "$HELPER_READY" -eq 1 ]; then
  HELPER_PUBKEY="$ROOT/config/privileged-helper-public.pem"
  "$NODE_BIN" "$SRC/privileged-helper-bootstrap.mjs" "$ENV_DST" "$ROOT/config/nc-device-key.pem" "$HELPER_PUBKEY" >/dev/null
  chown root:wheel "$HELPER_PUBKEY"
  chmod 0644 "$HELPER_PUBKEY"
  HELPER_SVC_UID="$(id -u "$USER_NAME")"
  HELPER_SVC_GID="$(id -g "$USER_NAME")"
  HELPER_CLIENT_ID="$(awk -F= '$1=="NC_CLIENT_ID"{print substr($0,index($0,"=")+1);exit}' "$ENV_DST")"
  printf '{"client_id":"%s","service_gid":%s,"service_uid":%s}\n' "$HELPER_CLIENT_ID" "$HELPER_SVC_GID" "$HELPER_SVC_UID" > "$ROOT/tmp/privileged-helper.json"
  install -m 0600 -o root -g wheel "$ROOT/tmp/privileged-helper.json" "$ROOT/config/privileged-helper.json"
  rm -f "$ROOT/tmp/privileged-helper.json"
  install -d -m 0750 -o root -g "$GROUP_NAME" /var/run/nc
  cat > "$ROOT/tmp/com.nc.privileged-helper.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.nc.privileged-helper</string>
<key>ProgramArguments</key><array><string>$NODE_BIN</string><string>$ROOT/app/privileged-helper-darwin-daemon.mjs</string></array>
<key>WorkingDirectory</key><string>$ROOT/app</string>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ProcessType</key><string>Background</string>
</dict></plist>
EOF
  install -m 0644 -o root -g wheel "$ROOT/tmp/com.nc.privileged-helper.plist" "$HELPER_PLIST"
  rm -f "$ROOT/tmp/com.nc.privileged-helper.plist"
  plutil -lint "$HELPER_PLIST"
  launchctl bootout system/com.nc.privileged-helper >/dev/null 2>&1 || true
  launchctl bootstrap system "$HELPER_PLIST"
  launchctl enable system/com.nc.privileged-helper
  sleep 2
  launchctl print system/com.nc.privileged-helper >/dev/null && echo 'NC privileged helper daemon active.' >&2
else
  launchctl bootout system/com.nc.privileged-helper >/dev/null 2>&1 || true
  rm -f "$HELPER_PLIST" "$ROOT/libexec/nc-darwin-peercred"
fi
fi
if [ "$BROWSER_READY" -eq 1 ]; then
  printf 'NC canonical install complete: %s (managed browser runtime ready)\n' "$ROOT"
else
  printf 'NC canonical install complete: %s (managed browser runtime NOT ready; browser tools hidden until installed)\n' "$ROOT"
fi
