# Project overview

AI Web Terminal running ttyd + tmux on the host, with a Docker stack for auth and storage.
Nginx (Docker) fronts the UI and terminal, the Node/Express API (Docker) handles JWT auth and
CRUD for prompts/users, and MySQL 8 stores data. The UI is a Preact/Vite build baked into the
nginx image and served from `/`.

## Architecture and flow
- Nginx listens on `127.0.0.1:8081` and proxies:
  - `/api/*` to the API container on `:3000`
  - `/ws`, `/token`, `/terminal` to ttyd on the host (`host.docker.internal:7681`)
- Auth:
  - `/login` is a static page at `nginx/login.html` that calls `POST /api/auth/login`
  - API sets `auth_token` and `terminal_token` as `HttpOnly` cookies (API also accepts `Authorization: Bearer ...`)
  - Nginx uses `auth_request` to validate cookies for the UI and terminal endpoints (no cookie→header mapping)
  - Bootstrap accounts may be redirected to `/change-password`
- First admin is bootstrapped by the API on startup when `users` is empty (env-driven or generated password).

## Key paths
- `docker-compose.yml` - Docker stack (nginx, api, mysql) + ports.
- `docker-compose.dev.yml` - Dev override (Vite UI + API watch mode).
- `api/src/index.js` - Express API, JWT auth, sessions, prompts, users.
- `api/migrations/`, `api/knexfile.cjs` - DB migrations (Knex).
- `db/init.sql` - legacy schema reference.
- `nginx/nginx.conf`, `nginx/login.html` - proxy + login page.
- `ui/` - Preact/Vite UI; build output to `ui/dist/` (copied into the nginx image).
- `scripts/docker-setup` - installs ttyd wrapper + user systemd service.
- `scripts/ui-build` - local UI build (for development).
- `scripts/ui-deploy` - installs tmux helper scripts and restarts ttyd (UI is shipped via nginx).
- `scripts/ai-tmux-windows`, `scripts/ai-tmux-complete` - tmux helpers for UI.

## Local setup / run
- Create `.env` from `.env.example` and set `MYSQL_ROOT_PASSWORD`, `MYSQL_PASSWORD`, `JWT_SECRET`.
- Install/start ttyd service: `./scripts/docker-setup`
- Start stack (builds nginx with UI): `docker compose up -d --build`

Optional dev workflows:
- API dev: `cd api && npm install && npm run dev`
- UI dev: `cd ui && npm install && npm run dev` (Vite dev server; not served by ttyd)

## Operational notes
- ttyd wrapper reads `~/.config/ai-webterm/ttyd.env` (`TTYD_BIND`, `TTYD_PORT_INTERACTIVE`).
- If you modify `scripts/ai-tmux-windows` or `scripts/ai-tmux-complete`, advise the user to run `bash ./scripts/ui-deploy` (it installs the helper scripts and restarts ttyd).
- `.env` is gitignored; do not commit secrets.
- Tailscale Serve setup lives in `docs/SETUP.md`.
- `TODO.md` is a proposal/backlog; treat as non-authoritative.

## Git policy
**NEVER run git commands for committing, pushing, or any repository operations on behalf of the user.** The user will handle all git operations themselves. This includes:
- `git add`
- `git commit`
- `git push`
- `git pull`
- `git merge`
- `git rebase`
- Any other git commands that modify the repository state

You may only use git for read-only operations like `git status`, `git log`, `git diff` when specifically needed to understand the codebase state.

## Tests
No automated tests are configured.
