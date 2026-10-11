# nc-agent

The official open-source native host agent and CLI installer for the [Node Command](https://nodecommand.app) enterprise platform.

Built strictly on native Node.js 24+ ECMAScript Modules (`.mjs`) with **zero external runtime dependencies**, `nc-agent` provides secure remote execution, browser automation, process monitoring, diagnostics, and outbound-only WebSocket tunnels.

---

## Quick Start (Device Pairing)

Pair a machine with your Node Command organization via the browser device authorization flow (RFC 8628):

```bash
npx nc-agent
```

This prints a one-time verification code and authorization URL. Once approved in the browser, the agent configures and starts automatically.

### CLI Subcommands

```bash
npx nc-agent setup            # Automatic mode (system service if root, user daemon otherwise)
npx nc-agent setup --system   # Force system-level service installation
npx nc-agent setup --user     # Force non-elevated user service installation
npx nc-agent remove           # Uninstall and remove the agent
npx nc-agent --diagnostics    # Generate and preview a redacted support bundle
```

---

## Standalone Development

External contributors can clone, run, test, and package `nc-agent` standalone without the private control-plane monorepo:

### Prerequisites

- Node.js >= 24.0.0
- Git

### Clone & Run

```bash
# Clone the repository
git clone https://github.com/huseyincig/nc-agent.git
cd nc-agent

# Run the agent runtime directly (zero npm install required)
npm start
```

### Running Tests

```bash
# Run the complete test suite
npm test

# Run specific tests
node --test tests/smoke.mjs
node --test tests/shell.test.mjs
node --test tests/browser.test.mjs
```

### Syntax Validation & Release Packaging

```bash
# Check syntax across all source files
node --check bin/nc.mjs src/client/launcher.mjs tests/*.mjs

# Package client distribution tarball
npm run package
```

---

## Repository Layout

```text
nc-agent/
├── bin/                 # CLI entrypoint (nc.mjs) and npx dispatcher
├── src/                 # Full agent runtime
│   ├── browser/         # Browser automation manager and Playwright integration
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

## Contributing

We welcome community contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on code style, testing requirements, security considerations, and how to submit pull requests.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
