# NC Agent Filesystem Layout

The runtime resolves its root directory from its own execution location (`<root>/app/launcher.mjs`), ensuring the identical layout functions across every installation mode. `NC_ROOT` is strictly unconfigurable at runtime and cannot be overridden via the environment.

## Installation Roots (Dual-Mode Install)

### Machine-Wide Roots (System Installs, Elevation Required)
- **Linux / macOS**: `/opt/nc`
- **Windows**: `C:\ProgramData\NC`

### Per-User Roots (User Installs, Zero Elevation)
- **Linux**: `~/.local/share/nc` (or `$XDG_DATA_HOME/nc`)
- **macOS**: `~/Library/Application Support/nc`
- **Windows**: `%LOCALAPPDATA%\NC`

> **Forbidden Paths**: Legacy paths `~/.nc` and `%APPDATA%\NC` are obsolete fossils and are strictly forbidden.

## Service and Process Modes

- **Linux**:
  - `NC_MODE=user`: Runs under `systemd --user` with linger enabled (`loginctl enable-linger`).
  - System mode: Runs under dedicated `_nc` service account using `/etc/systemd/system` unit.
- **Windows**:
  - Non-admin or `NC_USER_INSTALL=1`: Runs under user scheduled task triggered `AtLogOn`.
  - System mode: Runs under SCM as the `NCClient` service.
- **Runtime Standard**: The standalone `nc-agent.exe` binary is retired; standard execution runs via `node + launcher.mjs`.

## Subdirectory Structure

Under the resolved root `<root>`, the agent strictly isolates immutable application code from mutable state across seven subdirectories:

| Directory | Purpose |
| :--- | :--- |
| `app` | Live application code tree (`<root>/app/launcher.mjs`). Replaced atomically during updates (`nc-agent.exe` retired). |
| `config` | Static configuration and device credentials (`nc-client.env`, `nc-device-key.pem`). |
| `data` | Runtime state files (`client-state.json`, `client.pid`, `client.lock`, update status markers, workspaces). |
| `logs` | Runtime execution and security audits (`client.log`, `audit.jsonl`, `mcp-server.log`, `mcp-tunnel.log`). |
| `releases` | Staging area for downloaded updates (`releases/client`). |
| `backups` | Prior app versions retained for rollback (`backups/client`, migration backups; capped at max 10 backup generations). |
| `tmp` | Ephemeral operational files and scratch storage. |

## Privileged Helper IPC Endpoints

When elevated operations are required by system installations, communication with the privileged helper daemon occurs via OS-specific IPC channels:
- **Linux**: Unix domain socket at `/run/nc/privileged-helper-v1.sock`
- **macOS**: Unix domain socket at `/var/run/nc/privileged-helper-v1.sock`
- **Windows**: Named pipe at `\\.\pipe\NCPrivilegedV1`

The privileged helper enforces protocol `1.0.0`, 60-second TTL signed envelopes, a 64KB maximum payload size, and restricts operations to `client_uninstall`, `privileged_shell_exec`, and `service_control`.
