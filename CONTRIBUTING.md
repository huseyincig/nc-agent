# Contributing to nc-agent

Thank you for contributing to the Node Command native agent!

`nc-agent` is the open-source host agent that executes authorized commands, manages processes, runs browser automations, and streams diagnostic logs back to the Node Command platform.

---

## Architecture Principles

1. **Zero External Runtime Dependencies**: All runtime functionality is built strictly on native Node.js 24+ standard modules (`node:http`, `node:https`, `node:crypto`, `node:child_process`, `node:fs`, `node:path`, `node:os`). Do not introduce runtime npm dependencies.
2. **Strict ESM**: Use standard `.mjs` or ES module syntax. CommonJS `require()` is not supported.
3. **Fail-Closed Security**: Path inputs must always validate against directory traversal and symlink escapes (`src/filesystem/path-auth.mjs`). Redaction of sensitive values and credentials must be enforced (`redactSecretText`).
4. **Canonical Boundaries**:
   - Agent logic belongs in this repository (`nc-agent`).
   - Wire contract, schema, and MCP tool definition changes belong in [nc-protocol](https://github.com/huseyincig/nc-protocol).
   - Public wire changes require a protocol bump in `nc-protocol` first.

---

## Development Workflow

### 1. Prerequisites

- Node.js >= 24.0.0
- Git

### 2. Getting Started

```bash
# Clone your fork
git clone https://github.com/<your-username>/nc-agent.git
cd nc-agent

# Create a feature branch
git checkout -b feat/my-improvement
```

### 3. Running & Testing

```bash
# Run tests
npm test

# Run syntax checks
node --check bin/nc.mjs bin/nodecommand-agent.mjs src/client/launcher.mjs tests/*.mjs

# Package distribution tarball
npm run package
```

### 4. Adding Runtime Files

If you add a new `.mjs` file to `src/`:
1. Add the file name to `RUNTIME_FILES` in `scripts/package-release.mjs`.
2. Add its relative path to `SOURCE_PATHS` in `scripts/package-release.mjs`.
3. Verify that `npm test` passes (including the `runtime closure files exist` smoke test).

---

## Submitting Pull Requests

1. Ensure all tests pass (`npm test`) and syntax validation is clean.
2. Ensure no secrets, internal IPs, or environment keys are committed.
3. Commit with a clear, conventional commit message (`feat: ...`, `fix: ...`, `docs: ...`).
4. Open a Pull Request targeting `main`. Fill in the PR template with context, test evidence, and any relevant issue references.

All contributions are subject to the [Apache-2.0 License](LICENSE).
