# nc-agent

The official open-source native host agent and CLI installer for the
[Node Command](https://nodecommand.app) platform.

Built strictly on native Node.js ECMAScript Modules (`.mjs`) with **zero
external runtime dependencies**, `nc-agent` provides secure remote
execution, browser automation, process and service management, diagnostics,
and outbound-only WebSocket tunnels.

---

## Quick start

One command installs, enrolls, and verifies the agent on this machine:

```bash
npx node-command
```

The CLI prints an eight-character code and a verification URL. Open the URL
in your browser, sign in to your Node Command workspace, enter the code, and
approve. The agent then installs itself as a service — machine-wide when
elevated, per-user otherwise — and reports online. No inbound ports and no
firewall changes.

For hands-off enrollment, redeem the dashboard's one-time enrollment token
directly (single-use, short-lived):

```bash
npx node-command <host_id> <token>
```

### CLI reference

```bash
npx node-command                           # pair via browser device flow and install
npx node-command <host_id> <token>         # install; redeem the dashboard enrollment directly
npx node-command uninstall [--yes]         # remove the agent (alias: remove; confirms unless --yes)
npx node-command --diagnostics             # preview a redacted support bundle (writes nothing)
npx node-command --diagnostics --apply     # write the bundle for a support ticket
npx node-command --help                    # full usage
```

### npm packages

The same CLI is published under two npm package names:

- **`node-command`** (unscoped) — the primary package; new docs and
  scripts should use `npx node-command`.
- **`nc-agent`** — still published and actively maintained; `npx nc-agent`
  resolves to the identical CLI, and every command above works with either
  name.

Requirements: Node.js 24 or newer, on Linux, macOS, or Windows.

---

## What it does

- Executes admitted operations on the machine: shell commands, file reads
  and mutations, log queries and streams.
- Manages processes, services, OS packages, Git repositories, Docker
  containers, and GUI/browser sessions through a pinned Playwright runtime.
- Captures diagnostics and structured document extraction for AI analysis.
- Enforces host policy and network egress rules locally — capabilities
  default to deny until granted.
- Proves every request with an Ed25519 device key enrolled out-of-band.
- Updates itself from staged, hash-verified releases with automatic
  rollback on a failed health check.

---

## Standalone development

External contributors can clone, run, test, and package `nc-agent`
standalone without any private control-plane sources.

### Prerequisites

- Node.js >= 24.0.0
- Git

### Clone & run

```bash
# Clone the repository
git clone https://github.com/huseyincig/nc-agent.git
cd nc-agent

# Run the agent runtime directly (zero npm install required)
npm start
```

### Running tests

```bash
# Run the complete test suite
npm test

# Run specific tests
node --test tests/smoke.mjs
node --test tests/shell.test.mjs
node --test tests/browser.test.mjs
```

### Syntax validation & release packaging

```bash
# Check syntax across all source files
node --check bin/nc.mjs bin/nodecommand-agent.mjs src/client/launcher.mjs tests/*.mjs

# Package client distribution tarball
npm run package
```

---

## Repository layout

```text
nc-agent/
├── bin/                 # CLI entrypoint (nc.mjs) and npx dispatcher
├── src/                 # Full agent runtime
│   ├── browser/         # Pinned Playwright runtime and automation manager
│   ├── client/          # Core lifecycle, WebSocket client, state, launcher
│   ├── containers/      # Docker / Compose inspection and operations
│   ├── diagnostics/     # Health bundles and system diagnostics
│   ├── filesystem/      # File mutations, path traversal boundaries, path auth
│   ├── git/             # Local Git inspection and operations
│   ├── lifecycle/       # Agent startup, shutdown, and watchdog hooks
│   ├── logs/            # Structured logging and log streaming
│   ├── packages/        # OS package manager queries (apt, dnf, pacman, brew)
│   ├── policy/          # Host policy and network egress enforcement
│   ├── process/         # PTY and process session management
│   ├── services/        # System service managers (systemd, launchd, scm)
│   ├── shell/           # Command execution and output stream capturing
│   ├── structured-ops/  # Document extraction and project inspection
│   └── updater/         # Over-the-air (OTA) updates and tar extraction
├── installers/          # Native daemon installers (Linux systemd, macOS launchd, Windows)
├── privileged-helper/   # Privileged helper daemon and IPC contracts
├── gui-broker/          # GUI broker scripts for desktop integration
├── scripts/             # Release packaging and distribution tools
└── tests/               # Native node:test automated test suites
```

---

## Documentation

- [Filesystem layout and install roots](docs/FILESYSTEM_LAYOUT.md)
- [Migration and update runbook](docs/MIGRATION_RUNBOOK.md)
- [Uninstall](docs/UNINSTALL.md)
- [Security policy](SECURITY.md) — coordinated disclosure, trust model

---

## Related repositories

- [NodeCommand](https://github.com/huseyincig/NodeCommand) — product
  documentation, client examples, and manifests.
- [nc-protocol](https://github.com/huseyincig/nc-protocol) — the canonical
  wire contracts and MCP tool schemas implemented by this agent.

---

## Contributing

We welcome community contributions! Please read
[CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on code style, testing
requirements, security considerations, and how to submit pull requests.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
