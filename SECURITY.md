# Security Policy

## Supported versions

Latest `nc-agent` release only. The hub enforces a compatibility window
(current + previous agent minor); older agents are refused rollout and
flagged in fleet telemetry.

## Reporting a vulnerability

Email the maintainers (see GitHub repo security advisories) with:

- affected version(s) and platform
- reproduction steps or PoC
- impact assessment

Do NOT open a public issue for security reports. Expect acknowledgement
within 72 hours. Fixes ship as patch releases with a CHANGELOG entry;
credit on request.

## Trust model

- The agent never embeds hub credentials, tenant data, or signing keys.
  Device identity is a local Ed25519 keypair enrolled out-of-band.
- The privileged helper verifies every request (Ed25519 + policy binding +
  TTL + replay cache) and checks peer credentials on the local socket.
- Host policy is fail-closed: no policy → no privileged execution.
- Updates install only staged releases whose `sha256` matches the signed
  manifest and whose version is newer than the running one.
