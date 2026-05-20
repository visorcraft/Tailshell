<p align="center">
  <img src="ui/src/assets/images/1024x1024.png" alt="Tailshell mascot" width="200">
</p>

<h1 align="center">Tailshell</h1>

<p align="center">
  <strong>Your terminal, everywhere.</strong><br>
  A persistent web terminal that follows you from desktop to phone to tablet.
</p>

---

Tailshell wraps **ttyd** + **tmux** in a slick web UI with multi-user auth, workspaces, and quick prompts. Run it on your home server, access it from anywhere via Tailscale, and never lose a session again.

```
Browser ──> Nginx ──┬──> /api/* ──> API ──> MySQL
                    │
                    └──> /ws ──> ttyd ──> tmux ──> shell
```

## Why Tailshell?

- **Persistent sessions** — tmux keeps your work alive across disconnects
- **Workspaces & tabs** — organize projects with tmux sessions and windows
- **Quick Prompts** — save and recall commands, scoped to workspaces
- **Multi-user auth** — JWT-based login with MFA/TOTP for admins
- **Mobile-friendly** — works great on phones and tablets
- **Tailscale-ready** — secure access from anywhere, no port forwarding

## Quick Start

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

## Development

Want to hack on Tailshell? Fire up the dev stack with hot reload:

```bash
bash ./scripts/dev-up    # Start with Vite HMR + API watch
bash ./scripts/dev-down  # Tear it down
```

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

## License

This project is licensed under the GNU GPLv3. See `LICENSE`.
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for third-party components and licenses.
