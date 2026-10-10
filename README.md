# nc-agent

Node Command device pairing and agent installer.

## Install

```bash
npx nc-agent
```

This starts the browser device authorization flow (RFC 8628). It prints a
short confirmation code and a URL — open the URL in your browser, approve the
prompt, and the agent is enrolled, downloaded from the control plane,
installed, and verified automatically.

```bash
npx nc-agent setup            # explicit setup (auto system/user mode)
npx nc-agent setup --system   # force system-level service install
npx nc-agent setup --user     # force non-elevated user install
npx nc-agent remove           # uninstall the agent
npx nc-agent --diagnostics    # preview a redacted support bundle
```

The agent runtime is **not** bundled in this package. It is downloaded from
the control plane at install time, so a fresh `npx nc-agent` always installs
the latest release we serve. Updates after install flow through the Node
Command OTA channel, not npm.

## Environment

- `NC_BASE_URL` — auth host for the browser device flow (default `https://auth.nodecommand.app`)
- `NC_API_URL` — agent API host for device endpoints and package downloads (default `https://agent.nodecommand.app`)
- `NC_SERVER_URL` — agent server address written to the client env

## Manual install (fallback)

```bash
git clone https://github.com/huseyincig/nc-agent.git
cd nc-agent
npm start
```

## License

MIT — see [LICENSE](LICENSE).
