# Operations

## Start/Stop Services

```bash
# ttyd service (user-level, no sudo required)
systemctl --user start ai-ttyd-docker
systemctl --user stop ai-ttyd-docker
systemctl --user restart ai-ttyd-docker
systemctl --user status ai-ttyd-docker
journalctl --user -u ai-ttyd-docker -f  # view logs

# Docker stack
docker compose up -d
docker compose down
docker compose logs -f
```

Tip: if you use multiple compose files, set `COMPOSE_PROJECT_NAME=tailshell` to keep volumes stable across runs.

## Maintenance Mode

To temporarily block most API routes during migrations/outages:

1. Set `TAILSHELL_MAINTENANCE_MODE=true` in `.env`
2. Restart the API container:
   ```bash
   docker compose restart api
   ```

Notes:

- `/api/health`, `/api/ready`, and `/api/auth/validate` continue to work.
- Most other `/api/*` routes return `503` with `code: MAINTENANCE_MODE`.

## Database Migrations

Migrations run automatically when the API starts (Knex).

Manual run:

```bash
docker compose exec api npm run migrate
```

## Deploy UI Changes

UI changes are shipped via the nginx image.

```bash
cd /path/to/Tailshell
docker compose up -d --build nginx
```

Notes:

- If you changed tmux helper scripts (`scripts/ai-tmux-state`, `scripts/ai-tmux-window-status`, `scripts/ai-tmux-complete`, or legacy `scripts/ai-tmux-windows`), run `bash ./scripts/ui-deploy` (it installs helper scripts and restarts ttyd; active terminals may disconnect).
- If you changed ttyd wrapper/session scripts (`scripts/ai-ttyd-docker`, `scripts/ai-session`, `scripts/ai-ttyd-docker.user.service`), run `bash ./scripts/docker-setup`.

## Using the Terminal

**UI Controls:**

- **Tabs** (tmux windows): click to switch, `+` to add, `×` to close, drag to reorder, double-click to rename.
- **Workspaces** (tmux sessions): workspace dropdown + **Workspaces** modal for create/rename/pin/default/reorder/delete.
- **Compose**: per-tab drafts; Enter to send, Shift+Enter for newline, Tab for autocomplete.
- **Quick Prompts**: run in the active tab; per-user; optional multi-workspace scope (Manage from the prompt panel).
- **Copy transcript**: copies terminal scrollback (falls back to viewport/last lines). Selection copy uses native highlight + `Ctrl+C`.
- **Tools**: opens a tools modal (clipboard, settings, account actions).
- **Design Switcher**: bottom-right menu. Theme switcher remains only in **Classic**.

**tmux Shortcuts:**

- `Ctrl+B, N` - Next window
- `Ctrl+B, P` - Previous window
- `Ctrl+B, C` - New window

## Manage Users (Admin)

Requires `jq`.

```bash
# Get auth token
TOKEN=$(curl -s -X POST http://127.0.0.1:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}' | jq -r '.token')

# Create user
curl -X POST http://127.0.0.1:3000/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","password":"securepass123","role":"user"}'

# List users
curl http://127.0.0.1:3000/api/users -H "Authorization: Bearer $TOKEN"
```

## Reset Database (Deletes Data)

```bash
docker compose down -v
docker compose up -d --build
```

On next start the API will recreate the bootstrap admin (see `.env` or `docker compose logs api`).

## Docker Image Updates

This stack pins `mysql` and `nginx` image versions in `docker-compose.yml` for reproducible updates.

Update flow:

1. Edit pinned tags in `docker-compose.yml`
2. `docker compose pull`
3. `docker compose up -d --build`

## Backup Database

### Manual Backup

```bash
./scripts/mysql-backup
# Creates: backups/tailshell-YYYYMMDD-HHMMSS.sql.gz
```

### Scheduled Backups

Set up daily automated backups with automatic cleanup:

```bash
./scripts/backup-scheduler-setup
# Runs daily at 2:00 AM, keeps 7 days of backups
```

Commands:

```bash
systemctl --user status tailshell-backup.timer    # Check timer status
systemctl --user start tailshell-backup.service   # Run backup now
journalctl --user -u tailshell-backup -f          # View backup logs
```

### Restore Test

Verify backups can be restored:

```bash
./scripts/mysql-restore-test backups/tailshell-YYYYMMDD-HHMMSS.sql.gz
```

### Backup Drill

Run a full restore drill (tests the most recent backup):

```bash
./scripts/backup-drill
```

### Offsite Storage

See `docs/BACKUP-OFFSITE.md` for rclone, S3, Backblaze B2, and other offsite storage options.

## Centralized Logging

### Start Logging Stack

```bash
docker compose -f docker-compose.yml -f docker-compose.logging.yml up -d
```

Access Grafana at http://localhost:3100 (default: admin/admin).

### Features

- **Loki**: Log aggregation with 7-day retention
- **Promtail**: Collects logs from Docker containers (API, nginx, MySQL)
- **Grafana**: Pre-configured dashboard for viewing/querying logs

### Include ttyd Logs

To ship ttyd (host systemd) logs to Loki:

```bash
./scripts/promtail-host-setup
```

### Log Queries

In Grafana, use LogQL to query logs:

```
{service="api"}                           # All API logs
{service="nginx"} |= "500"                # Nginx 5xx errors
{service=~".+"} |~ "(?i)error"            # Errors across all services
```

## ttyd Health Monitoring

### Health Check

```bash
./scripts/ttyd-health-check
# Returns: HEALTHY or UNHEALTHY with reason
```

### Watchdog (Auto-Restart)

Set up automatic health monitoring and restart:

```bash
./scripts/ttyd-watchdog-setup
# Checks every 30 seconds, restarts if unhealthy
```

Commands:

```bash
systemctl --user status ttyd-watchdog.timer  # Check watchdog status
journalctl --user -u ttyd-watchdog -f        # View watchdog logs
```
