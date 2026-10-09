# nc-agent

Public Node Command endpoint runtime (Linux / Windows / macOS). Canonical agent source.

## What runs on your device

Connection runtime, device authentication, shell/filesystem execution,
browser adapter, egress enforcement, host-policy enforcement, privileged
helper, GUI broker, self-updater, installers, uninstall.

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
