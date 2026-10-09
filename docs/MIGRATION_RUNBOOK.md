# NC Agent Migration Runbook

A client migration updates the agent runtime while preserving the existing client identity, device key (`nc-device-key.pem`), client token material, and mutable state. No new enrollment token is needed for migration.

## Root Resolution and Install Modes

Installations follow the dual-mode structure. The agent root is resolved from the runtime launcher location; `NC_ROOT` is unconfigurable at runtime.

- **System Roots**: `/opt/nc` (Linux/macOS) and `C:\ProgramData\NC` (Windows).
- **User Roots**: `~/.local/share/nc` (`$XDG_DATA_HOME/nc`), `~/Library/Application Support/nc` (macOS), and `%LOCALAPPDATA%\NC` (Windows).
- **Forbidden Paths**: Legacy `~/.nc` and `%APPDATA%\NC` are obsolete fossils and are strictly forbidden.

### Service Manager Integration
- **Linux**:
  - `NC_MODE=user`: Managed via `systemd --user` with linger enabled (`loginctl enable-linger`).
  - System mode: Managed via `/etc/systemd/system` unit running under the `_nc` service account.
- **Windows**:
  - Non-admin or `NC_USER_INSTALL=1`: Managed via user scheduled task triggered `AtLogOn`.
  - System mode: Managed via the `NCClient` Windows service.

## Directory Layout Preservation

The canonical layout maintains seven discrete subdirectories under `<root>`:
- `app`: Live agent runtime (`node + launcher.mjs`; `nc-agent.exe` is retired).
- `config`: Preserved during migration (`nc-client.env`, `nc-device-key.pem`).
- `data`: Preserved runtime state (`client-state.json`, workspace, markers).
- `logs`: Agent and tunnel execution logs (`client.log`, `audit.jsonl`).
- `releases`: Update staging directory (`releases/client`).
- `backups`: Rollback targets (`backups/client`; pruned to a maximum of 10 backup generations).
- `tmp`: Ephemeral working files.

## Migration and Update Execution Workflow

1. **Rollout Assignment**: The hub coordinates staged updates using rollout buckets.
2. **Staging**: The candidate release is staged in `<root>/releases/client/` and verified.
3. **Atomic App Swap**: The current `app` directory is moved to `<root>/backups/client/previous-<timestamp>`, and the staged tree is moved to `app`. Legacy binaries such as `nc-agent.exe` are purged, standardizing on `node + launcher.mjs`.
4. **Health Gate Validation**: The new runtime starts and must create a healthy marker (`data/healthy-<version>-<stamp>`) within a 25-second gate.
5. **Rollback Mechanism**: If the healthy marker is not confirmed within the 25-second window, an in-process rollback (`app` → `previous`) restores the prior functional release.
6. **Backup Retention**: Older rollback backups are pruned automatically, retaining a maximum of 10 backup generations.

## Privileged Helper Operations

For elevated maintenance during migration or service management, the agent communicates with the privileged helper daemon:
- **Protocol**: Version `1.0.0`
- **Envelope Security**: 60-second TTL signed envelopes, maximum payload size of 64KB
- **Allowed Operations**: `client_uninstall`, `privileged_shell_exec`, `service_control`
- **IPC Transports**:
  - Linux/macOS: Unix domain sockets (`/run/nc/privileged-helper-v1.sock`, `/var/run/nc/privileged-helper-v1.sock`)
  - Windows: Named pipe `\\.\pipe\NCPrivilegedV1`
