# nc-agent

Public Node Command endpoint runtime (Linux / Windows / macOS). Canonical agent source.

## What runs on your device

Connection runtime, device authentication, shell/filesystem execution,
browser adapter, egress enforcement, host-policy enforcement, privileged
helper, GUI broker, self-updater, installers, uninstall.

## Installation

Install the agent on Linux, macOS, or Windows using `npx`:

```bash
npx nc-agent
```

This automatically detects your operating system and invokes the corresponding native installer.

### Advanced Options & Configuration

Configuration flags can be passed via environment variables:

- `NC_ROOT`: Target installation directory.
  - Linux: default `/opt/nc` (system) or `~/.local/share/nc` (user mode).
  - macOS: default `/opt/nc` (system) or `~/Library/Application Support/nc` (user mode).
  - Windows: default `C:\NC`.
- `NC_USER_INSTALL=1`: Force user-level installation without root or administrative elevation.
- `NC_SYSTEM_INSTALL=1`: Require system-level service installation (requires root/admin elevation).

Example (user-mode installation):

```bash
NC_USER_INSTALL=1 npx nc-agent
```

### Manual Installation (from Git)

If you prefer to install without `npx`, clone the repository and run the installer directly:

```bash
git clone https://github.com/huseyincig/nc-agent.git
cd nc-agent

# Linux
bash installers/linux/install-linux.sh

# macOS
bash installers/macos/install-macos.sh

# Windows (Run PowerShell as Administrator)
powershell -NoProfile -ExecutionPolicy Bypass -File installers\windows\install-windows.ps1
```

## Layout

```text
src/                client runtime, ops, policy, updater, lifecycle
privileged-helper/  root helper daemon + IPC contract
gui-broker/         per-session GUI broker
installers/         linux / macos / windows installers + services
tests/              smoke + unit tests
scripts/            release packaging (package-release.mjs)
docs/               layout / migration / uninstall guides
```

`src/shell/` is reserved for the planned extraction of shell execution out
of `src/client/client.mjs` (`executeShellJob`); see `src/shell/README.md`.

## Wire contract

Everything the agent and the hub must agree on lives in
[`nc-protocol`](https://github.com/huseyincig/nc-protocol). This repo
depends on `nc-protocol` releases; it never depends on private hub source.

## Security

See `SECURITY.md` and `THREAT_MODEL.md`. Report vulnerabilities via the
process in `SECURITY.md` — never as public issues.
