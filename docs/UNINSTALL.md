# NC Agent Uninstall

Uninstallation removes the local NC agent runtime and service integrations while preserving device identity and credentials (`nc-device-key.pem`, client tokens) in `config/` unless explicitly purged. No new enrollment token is needed if the host is re-migrated or reconnected. Server-side identity removal remains a separate, explicit control-plane operation and must never be silently inferred from local file deletion.

## Uninstaller Invocation and Root Resolution

The uninstall process uses the platform uninstaller script (`<root>/uninstall.sh` on Linux/macOS or `<root>/uninstall.ps1` on Windows) or the privileged helper IPC.

The uninstaller resolves its target root from its own directory structure. `NC_ROOT` is strictly unconfigurable at runtime.

### Dual-Mode Uninstall Targets
- **System Roots (Elevation Required)**:
  - Linux / macOS: `/opt/nc`
  - Windows: `C:\ProgramData\NC`
- **Per-User Roots (Zero Elevation Required)**:
  - Linux: `~/.local/share/nc` (or `$XDG_DATA_HOME/nc`)
  - macOS: `~/Library/Application Support/nc`
  - Windows: `%LOCALAPPDATA%\NC`
- **Forbidden Paths**: Legacy `~/.nc` and `%APPDATA%\NC` are obsolete fossils and are strictly forbidden.

## Service Teardown by Platform

- **Linux**:
  - `NC_MODE=user`: Stops and unregisters the `systemd --user` unit and cleans up user service links.
  - System mode: Stops and removes `/etc/systemd/system/nc-client.service`, terminating processes owned by the `_nc` service account.
- **Windows**:
  - Non-admin or `NC_USER_INSTALL=1`: Deregisters the `AtLogOn` user scheduled task.
  - System mode: Stops and removes the `NCClient` Windows service via SCM.
- **Runtime Processes**: Terminates active `node + launcher.mjs` runtime processes (`nc-agent.exe` is retired).

## Layout and Filesystem Cleanup

The uninstaller manages standard subdirectories under `<root>`:
- `app`: Runtime binaries and launcher scripts removed (`node + launcher.mjs`; `nc-agent.exe` retired).
- `config`: Preserved to retain device identity (`nc-device-key.pem`) and environment (`nc-client.env`) unless an explicit purge flag is passed.
- `data`: State and lock files cleared (`client-state.json`, `client.pid`, `client.lock`, workspaces).
- `logs`: Log files (`client.log`, `audit.jsonl`, `mcp-server.log`, `mcp-tunnel.log`) optionally archived or cleaned.
- `releases`: Staged update directories cleared.
- `backups`: Previous versions and rollback archives cleared (historical limit of max 10 backup generations).
- `tmp`: Scratch files purged.

## Elevated Uninstall via Privileged Helper

When system uninstallation is initiated remotely or from an unprivileged control context:
- **Protocol**: Version `1.0.0`
- **IPC Endpoints**:
  - Linux/macOS: Unix domain sockets (`/run/nc/privileged-helper-v1.sock` or `/var/run/nc/privileged-helper-v1.sock`)
  - Windows: Named pipe `\\.\pipe\NCPrivilegedV1`
- **Envelope Constraint**: 60-second TTL signed envelopes, 64KB maximum payload size
- **Operation**: Dispatches the `client_uninstall` operation (one of three supported operations: `client_uninstall`, `privileged_shell_exec`, `service_control`) to stop services and remove system-level artifacts cleanly.
