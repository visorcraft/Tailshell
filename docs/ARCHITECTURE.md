# Architecture

## Components

```
Browser ──> Nginx :8081 ──┬──> /api/* ──> API ──> MySQL
            (Docker)      │                (Docker)
                          │
                          └──> /ws|/token|/terminal ──> ttyd :7681 ──> tmux ──> shell
                                      └─── runs on HOST (WSL) ───┘
```

- **Nginx (Docker)** is the single front door. It serves the UI and proxies:
  - `/api/*` → API container
  - `/ws`, `/token`, `/terminal` → host `ttyd`
- **API (Docker / Node+Express)** handles auth (short-lived access + rotating refresh tokens), RBAC, user management, audit logs, and prompt CRUD.
- **MySQL 8 (Docker)** stores users, prompts, and sessions/metadata.
- **ttyd + tmux (Host / WSL)** runs interactive shells. Nginx passes a non-spoofable per-user key so each user/session maps to an isolated tmux session, with per-user concurrency limits.

## Key Files

- `docker-compose.yml` - service definitions and port bindings
- `nginx/nginx.conf` - proxy rules, caching, and CSP
- `nginx/Dockerfile` - multi-stage build (build UI, bake into nginx image, enable brotli)
- `api/src/index.js` - API routes and auth
- `ui/` - Preact/Vite UI source
- `scripts/docker-setup` - installs ttyd wrapper + user systemd service
- `scripts/ui-deploy` - installs tmux helper scripts and restarts ttyd (only needed when those scripts change)
