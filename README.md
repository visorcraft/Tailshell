<p align="center">
  <img src="assets/Tailshell.png" alt="Tailshell mascot" width="200">
</p>

<h1 align="center">Tailshell</h1>

<p align="center">
  <b>Your terminal, everywhere.</b>
  <br />
  A persistent web terminal that follows you from desktop to phone to tablet.
  <br />
  Persistent sessions · multi-user auth · mobile-friendly · Tailscale-ready
</p>

<p align="center">
  <img src="https://img.shields.io/badge/terminal-ttyd%20%2B%20tmux-2E8B57" alt="ttyd + tmux" />
  <img src="https://img.shields.io/badge/deploy-Docker%20Compose-2496ED?logo=docker&logoColor=white" alt="Docker Compose" />
  <img src="https://img.shields.io/badge/access-Tailscale-242424?logo=tailscale&logoColor=white" alt="Tailscale" />
  <img src="https://img.shields.io/badge/license-GPL--3.0--only-blue" alt="License: GPL-3.0-only" />
</p>

---

## Overview

Tailshell wraps **ttyd** + **tmux** in a slick web UI with multi-user auth, workspaces, and quick prompts. Run it on your home server, access it from anywhere via Tailscale, and never lose a session again.

```
Browser ──> Nginx ──┬──> /api/* ──> API ──> MySQL
                    │
                    └──> /ws ──> ttyd ──> tmux ──> shell
```

---

## Why Tailshell?

- **Persistent sessions** — tmux keeps your work alive across disconnects
- **Workspaces & tabs** — organize projects with tmux sessions and windows
- **Quick Prompts** — save and recall commands, scoped to workspaces
- **Multi-user auth** — JWT-based login with MFA/TOTP for admins
- **Mobile-friendly** — works great on phones and tablets
- **Tailscale-ready** — secure access from anywhere, no port forwarding

---

## Quick start

```bash
# Clone and enter the repo
cd /path/to/tailshell

# Generate secrets
bash ./scripts/generate-env

# Set up ttyd + systemd service
bash ./scripts/docker-setup

# Launch everything
docker compose up -d --build
```

Open `http://localhost:8081/` and log in. First-time setup will prompt you to change the bootstrap password.

> **Tip:** Set `TAILSHELL_ADMIN_USERNAME` and `TAILSHELL_ADMIN_PASSWORD` in `.env` before first run, or check `docker compose logs api` for the generated credentials.

---

## Development

Want to hack on Tailshell? Fire up the dev stack with hot reload:

```bash
bash ./scripts/dev-up    # Start with Vite HMR + API watch
bash ./scripts/dev-down  # Tear it down
```

---

## Documentation

The good stuff lives in [`docs/`](docs/README.md):

| Doc | What's inside |
|-----|---------------|
| [Setup](docs/SETUP.md) | Full installation guide (WSL, systemd, Tailscale Serve) |
| [Operations](docs/OPERATIONS.md) | Day-to-day commands, backups, user management |
| [Architecture](docs/ARCHITECTURE.md) | How the pieces fit together |
| [Security](docs/SECURITY.md) | CORS, TLS, CSP, and hardening |
| [API](docs/API.md) | Endpoint reference |
| [Development](docs/DEVELOPMENT.md) | UI/API dev workflows |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and fixes |

---

## Contribute

Issues and PRs are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development workflow, and [`SECURITY.md`](SECURITY.md) for reporting security issues privately.

---

## License

Licensed under the **GNU General Public License v3.0** (`GPL-3.0-only`) — see [`LICENSE`](LICENSE) for the full text.

© 2026 VisorCraft LLC. Third-party components carry their own licenses — see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and the [`LICENSES/`](LICENSES/) directory.
