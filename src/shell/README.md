# src/shell

Canonical home of shell execution (`executeShellJob` + helpers
`normalizedJobPayload`, `shellEnvironment`, `shellInvocation`,
`shellChildDetached`, `terminateShellTree`, `appendLimited`).

Design: pure with respect to the daemon. Host limits arrive via `runtime`
(`{root, maxTimeoutSeconds, maxStdoutBytes, maxStderrBytes}`); the daemon
(`src/client/client.mjs`) passes them from its config. Tests:
`tests/shell.test.mjs`.
