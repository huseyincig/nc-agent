# Threat Model

## Assets

User device integrity, local files, shell execution, browser sessions,
device identity key, update channel integrity.

## Actors

- **Local unprivileged attacker:** other users/processes on the device.
- **Network attacker:** MITM on device↔hub traffic (TLS assumed; policy
  application additionally requires HTTPS unless explicitly opted out).
- **Malicious hub content:** a compromised hub issuing hostile jobs.
- **Malicious local peer:** process impersonating the agent to the helper.

## Boundaries & mitigations

| Boundary | Mitigation |
|---|---|
| Device ↔ hub | TLS + per-request device proof (Ed25519, replay cache, expiry) |
| Agent ↔ helper | Unix socket UID/GID/mode checks + `SO_PEERCRED` + signed requests + TTL + replay set |
| Hub → device jobs | Host-policy admission, capability binding, roots confinement, egress/SSRF denylist |
| Update channel | Staged dir + sha256 match + newer-version gate + healthy-marker + rollback |
| Multi-user device | Helper socket `root:nc 0660`; config `root:root 0600`; no world-readable secrets |

## Non-goals

Hub-side tenant isolation, billing fraud, and cloud infrastructure
threats are out of scope for this repository.
