<!-- SPDX-FileCopyrightText: 2026 VisorCraft LLC -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Contributing to Tailshell

Thank you for helping improve Tailshell. The project is a web
application that wraps **ttyd** + **tmux** behind a Node.js + Preact
front end, fronted by nginx, with MySQL for persistent state. Changes
should be small, tested, and aligned with the existing service
boundaries.

## Contribution workflow

1. Fork the repository on GitHub.
2. Clone your fork:

   ```bash
   git clone https://github.com/<you>/tailshell.git
   cd tailshell
   ```

3. Create a focused branch:

   ```bash
   git checkout -b fix-workspace-rename
   ```

4. Install the development prerequisites described in
   [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) (Node 22 + Docker
   Compose are the basics).
5. Make the smallest change that fully solves the issue.
6. Add or update tests and documentation.
7. Run the local gate before pushing:

   ```bash
   npm run format:check
   npm run lint
   (cd ui  && npm run typecheck)
   (cd api && npm test)
   (cd ui  && npm test)
   ```

8. Push your branch and open a pull request against `master`.

Pull requests should include a clear summary, the tests you ran, and
screenshots when the change affects the UI.

## Project layout

- `api/` — Node.js + Express API (auth, workspaces, prompts, audit).
  Database access goes through Knex; migrations live in
  `api/migrations/`.
- `ui/` — Preact + Vite single-page app served as static files by
  nginx. The terminal is `@xterm/xterm` wrapped in our shell.
- `nginx/` — reverse proxy + static auth pages (login, invite,
  password reset). The dev config is `nginx.dev.conf`; the prod
  config is `nginx.conf`.
- `db/` — MySQL bootstrap SQL.
- `docs/` — architecture, setup, development, operations,
  security, backup, and release notes.
- `scripts/` — Bash helpers (`dev-up`, `dev-down`, backup tooling,
  TLS helpers).
- `logging/` — optional Loki / Promtail compose for centralized logs.
- `assets/` — master brand imagery (see `assets/README.md`).

Keep API logic in `api/`. The UI should call API endpoints rather
than reimplement business rules. Terminal state (tmux sessions,
ttyd connections) is the API's responsibility; the UI is a thin
client.

## Local development

The fastest path is the one-shot dev stack:

```bash
bash ./scripts/dev-up      # nginx + Vite (HMR) + API (watch) + MySQL
bash ./scripts/dev-down    # tear it back down
```

Or run pieces independently:

```bash
# API (auto-reloads on save)
cd api && npm install && npm run dev

# UI (Vite dev server with HMR)
cd ui && npm install && npm run dev

# Migrations
cd api && npm run migrate
```

When the dev stack is up:

- UI: <http://localhost:5173>
- API: <http://localhost:8081/api/>
- Nginx (compose front door): <http://localhost:8080>
- MySQL: localhost:3306 (credentials from `.env`)

## Coding standards

- Target **Node 22** (Node 20.19+ is the floor). Use ESM (`type:
  module`), top-level `await` where it reads cleanly, and the modern
  `node:` core imports.
- Format every file with Prettier:

  ```bash
  npm run format
  npm run format:check
  ```

- Lint every file with ESLint:

  ```bash
  npm run lint
  npm run lint:fix
  ```

  The lint step runs both `api/` and `ui/`.

- UI: Preact + plain CSS modules. Functional components only. State
  via Preact hooks; pull shared logic into `ui/src/hooks/` rather
  than duplicating across components.
- API: prefer explicit, small handlers. Database access goes through
  the existing Knex query builders; new tables need a migration in
  `api/migrations/`.
- Logging: server-side logging goes through the existing logger
  module — do not `console.log` from request handlers in committed
  code.
- Errors: do not swallow them. Surface API errors as structured
  JSON; surface UI errors through the toast / error-banner pattern.

Every new source file must include the SPDX short header:

```text
SPDX-FileCopyrightText: 2026 VisorCraft LLC
SPDX-License-Identifier: GPL-3.0-only
```

Use the comment syntax appropriate for the file type (`//` for JS /
TS, `<!-- ... -->` for HTML, `#` for shell / nginx config).

## Tests

Match test coverage to the risk of the change:

- API: unit + integration tests under `api/src/**/__tests__/`. Hit
  the real database through a transactional helper rather than
  mocking Knex.
- UI: component tests next to the component file. Add a smoke test
  for any new route or top-level container.
- Cross-service behavior (auth flows, terminal handshakes, audit
  log emission): integration tests under `api/test/integration/`.

Run the same gate CI uses before opening a pull request:

```bash
npm run lint
(cd ui  && npm run typecheck && npm test)
(cd api && npm test)
```

## Database migrations

- Add a new Knex migration in `api/migrations/` instead of editing an
  existing one. Filename pattern follows the existing
  `YYYYMMDDHHMMSS_description.cjs` convention.
- Migrations must be **idempotent** and **forward-only**. Tailshell
  does not roll back; the `down` function should at minimum be safe
  to run.
- Touch `db/init.sql` only when bootstrapping a brand-new column or
  table that the migration assumes is already present in fresh
  installations.

## Pull request expectations

A good pull request:

- Has one clear purpose.
- Describes user-visible behavior changes.
- Calls out migrations, secrets, or compatibility risks.
- Includes tests, or explains why tests are not practical.
- Updates docs (`docs/API.md`, `docs/OPERATIONS.md`, `docs/SECURITY.md`,
  the README, etc.) when behavior changes.
- Passes lint, typecheck, and the API + UI test suites.
- Avoids unrelated formatting or refactoring churn.

Maintainers may ask for smaller commits, additional tests, or docs
updates before merging.

## Dependency policy

Tailshell is GPL-3.0-only. New npm packages must use licenses
compatible with GPL-3.0 (MIT, Apache-2.0, BSD-*, ISC, etc.). Avoid
new dependencies unless they clearly reduce complexity or provide
well-tested domain behavior that should not be maintained locally.

Dependabot opens weekly PRs against `master`; please skim them and
merge once CI is green.

## Security

Do not report security issues through public issues or pull
requests. Follow the disclosure policy in [SECURITY.md](SECURITY.md),
and consult [docs/SECURITY.md](docs/SECURITY.md) for the operational
hardening checklist that production deployments are expected to
follow.
