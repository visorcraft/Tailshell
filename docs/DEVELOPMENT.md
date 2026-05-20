# Development

## Node.js

Host Node is only needed for local development (Vite dev server, running the API outside Docker, installing CLIs).

UI dev/build requires Node 22 (or Node 20.19+). On Ubuntu 24.04, an easy install path is NodeSource:

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
node -v
npm -v
```

## API dev

```bash
cd api
npm install
npm run dev
```

## UI dev

```bash
cd ui
npm install
npm run dev
```

## Docker dev stack (one command)

Run nginx + Vite (HMR) + API (watch) + MySQL:

```bash
bash ./scripts/dev-up
```

Stop it:

```bash
bash ./scripts/dev-down
```

## Linting & Type Checking

Both API and UI have ESLint configured. CI enforces lint checks on all PRs.

### API (JavaScript)

```bash
cd api
npm run lint        # Check for issues
npm run lint:fix    # Auto-fix issues
```

### UI (TypeScript)

```bash
cd ui
npm run lint        # Check for issues
npm run lint:fix    # Auto-fix issues
npm run typecheck   # TypeScript type checking
```

### Formatting

A shared Prettier config (`.prettierrc`) is used across the project:
- Single quotes
- Semicolons
- 2-space indent
- 120 character line width

Notes:
- The Vite dev server is a different origin by default (`http://localhost:5173`), so set `CORS_ORIGIN=http://localhost:5173` in `.env` if you want the browser to call the API directly during UI dev.
- Production UI is shipped via the nginx image; see `docs/OPERATIONS.md` for deployment.

## Install Claude Code / Codex CLI (optional)

```bash
# Claude Code
curl -fsSL https://claude.ai/install.sh | bash

# Codex CLI
npm i -g @openai/codex
```
