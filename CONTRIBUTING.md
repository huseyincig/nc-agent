# Contributing

- One component, one canonical repo: agent changes belong here, wire
  contract changes belong in `nc-protocol`, hub changes in `nc-platform`.
- Public wire behavior changes require a protocol version bump first.
- Every change: `node --check` clean, related tests green, no secrets or
  internal topology in code or docs.
- Installers and the updater share one runtime file contract
  (`scripts/package-release.mjs` `RUNTIME_FILES`); keep them in sync.
- Run the release build (`node scripts/package-release.mjs --force`) before
  submitting updater/installer changes.
- License: contributions under Apache-2.0.
