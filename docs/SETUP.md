# Setup

This guide covers full machine setup (WSL + ttyd + Docker) and bringing the stack up for the first time.

## Quick Start (already have prerequisites)

```bash
cd /path/to/Tailshell

# Generate strong secrets (writes .env if missing)
bash ./scripts/generate-env

# Install/refresh ttyd wrapper + user systemd service
bash ./scripts/docker-setup

# Start the Docker stack (builds nginx image which includes the UI)
docker compose up -d --build
```

Optional (Docker secrets):

```bash
docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d --build
```

Access: `http://localhost:8081/` or `https://<hostname>.<tailnet>.ts.net/`

Bootstrap admin:

- Recommended: set `TAILSHELL_ADMIN_USERNAME` / `TAILSHELL_ADMIN_PASSWORD` in `.env`
- Otherwise: check `docker compose logs api` for a generated password on first run
- On a fresh DB you’ll be redirected to `/change-password` until you rotate it

## Host Prerequisites (Windows 11 + WSL2 + Ubuntu 24.04)

### 1) Install WSL2 + Ubuntu 24.04

In **Windows PowerShell**:

```powershell
wsl --install -d Ubuntu-24.04
wsl --update
wsl -l -v
```

### 2) Enable systemd in WSL

In **Ubuntu (WSL)**:

```bash
sudo sh -c 'echo -e "[boot]\nsystemd=true" > /etc/wsl.conf'
```

In **Windows PowerShell**:

```powershell
wsl --shutdown
```

Reopen Ubuntu and verify: `ps -p 1 -o comm=` should show `systemd`.

### 3) Install packages

In **Ubuntu (WSL)**:

```bash
sudo apt-get update && sudo apt-get -y upgrade

sudo apt-get install -y \
  git curl ca-certificates openssl \
  build-essential cmake \
  libjson-c-dev libwebsockets-dev \
  tmux ripgrep htop \
  jq
```

### 4) Build and install ttyd

```bash
cd ~
git clone https://github.com/tsl0922/ttyd.git
cd ~/ttyd && git checkout 1.7.7
mkdir -p build && cd build
cmake .. && make -j"$(nproc)"
sudo make install
ttyd --version  # Should show 1.7.7
```

### 5) Install Docker

Follow Docker’s official Ubuntu guide or use Docker Desktop for Windows with WSL2 backend.

## Repo Setup

### 1) Generate `.env`

```bash
cd /path/to/Tailshell
bash ./scripts/generate-env
```

If you already have an existing MySQL Docker volume, changing `MYSQL_*` values later won’t automatically update the DB users. The fastest reset is:

```bash
docker compose down -v && docker compose up -d --build
```

### 2) Install ttyd wrapper + user systemd service

```bash
bash ./scripts/docker-setup
```

This script:

- Installs the ttyd wrapper (`~/.local/bin/ai-ttyd-docker`)
- Installs a **user-level** systemd service (no root required for management)
- Enables user lingering (keeps service running after logout)
- Cleans up any old system-level services
- Starts the ttyd service

### 3) Start the Docker stack

```bash
docker compose up -d
docker compose ps
```

Expected:

```
NAME          STATUS                  PORTS
tailshell-mysql    running (healthy)       127.0.0.1:3307->3306/tcp
tailshell-api      running                 127.0.0.1:3000->3000/tcp
tailshell-nginx    running                 127.0.0.1:8081->80/tcp
```

### 3b) (Optional) Enable TLS + HTTP/2 directly in nginx

If you want nginx (not Tailscale) to terminate TLS and serve HTTP/2:

1. Put your cert + key in `nginx/certs/` as:
   - `nginx/certs/tls.crt`
   - `nginx/certs/tls.key`
2. Set `TAILSHELL_COOKIE_SECURE=true` in `.env`
3. Start the stack with the TLS override:

```bash
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d --build
```

Access: `https://localhost:8443/`

### 4) (Optional) Configure Tailscale Serve (Windows PowerShell)

Tailscale Serve is the recommended way to access this stack remotely over HTTPS inside your tailnet.

Notes:

- Avoid public exposure (don’t use Tailscale Funnel unless you explicitly want it public).
- Enabling HTTPS certificates issues trusted certs for your `*.ts.net` hostname; your device name may appear in certificate transparency logs, so avoid sensitive names.
- Tailscale Serve runs on **Windows** and proxies to **Windows localhost**. If `curl http://localhost:8081/` doesn’t work in Windows, ensure WSL localhost forwarding is enabled (see below).

```powershell
tailscale serve reset
tailscale serve --bg --yes 8081
tailscale serve status
```

If Windows can’t reach the stack at `http://localhost:8081/`, ensure WSL localhost forwarding:

1. Create/edit `%UserProfile%\.wslconfig`:
   ```ini
   [wsl2]
   localhostForwarding=true
   ```
2. Restart WSL:
   ```powershell
   wsl --shutdown
   ```

### 5) First login

1. Open `http://localhost:8081/` (or your Tailscale URL)
2. Login with the bootstrap admin credentials (from `.env` or `docker compose logs api`)
3. Complete `/change-password` to continue (required on first login for a fresh DB)

## Optional: Install Claude Code / Codex CLI

This is only needed if you want to run these tools on the host. It requires Node.js.

```bash
# Claude Code
curl -fsSL https://claude.ai/install.sh | bash

# Codex CLI
npm i -g @openai/codex
```

## Optional: Manual host scripts (advanced)

You typically do not need these steps because `scripts/docker-setup` installs/updates them automatically.

### `ai-session` (tmux bootstrap)

The canonical entrypoint lives at `scripts/ai-session` and is installed by `bash ./scripts/docker-setup`.
If you change it, re-run `bash ./scripts/docker-setup` to reinstall and restart ttyd.

### tmux config

```bash
cat > ~/.tmux.conf <<'CONF'
set -g mouse on
set -g status off
set -g history-limit 50000
set -g alternate-screen off
set -ga terminal-overrides ",xterm*:smcup@:rmcup@"
CONF
```

### ttyd config

```bash
mkdir -p ~/.config/ai-webterm

cat > ~/.config/ai-webterm/ttyd.env <<'ENV'
TTYD_BIND=0.0.0.0
TTYD_PORT_INTERACTIVE=7681
ENV

chmod 600 ~/.config/ai-webterm/ttyd.env
```
