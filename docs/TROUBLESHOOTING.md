# Troubleshooting

## “Invalid credentials” on login

Reset database (deletes data):

```bash
docker compose down -v && docker compose up -d --build
```

## MySQL “Access denied” / API fails to start

If the MySQL Docker volume already exists, changing `MYSQL_*` values in `.env` will not automatically update DB user passwords. The quickest fix is a full reset (deletes DB):

```bash
docker compose down -v && docker compose up -d --build
```

## Rotated secrets (JWT / DB)

- If you change `JWT_SECRET`, all existing sessions/tokens become invalid. Clear site cookies (or hit `/logout`) and log in again.
- If you change MySQL passwords (`MYSQL_*`) on an existing `mysql_data` volume, the container won’t automatically update the stored user credentials. Either update them in MySQL or reset the volume (see above).

## Login loop / can’t stay logged in

Most common cause is cookie hardening mismatch:

- Accessing over plain HTTP (`http://localhost:8081`): keep `TAILSHELL_COOKIE_SECURE` empty/false.
- Accessing over HTTPS (e.g. Tailscale Serve URL): set `TAILSHELL_COOKIE_SECURE=true`, then restart the stack.

Then clear cookies for the site (or hit `/logout`) and try again.

## Permission denied running scripts

If `./scripts/...` fails with `Permission denied`, run via bash:

```bash
bash ./scripts/generate-env
bash ./scripts/docker-setup
```

## ttyd showing errors or not starting

Check service status:

```bash
systemctl --user status ai-ttyd-docker
journalctl --user -u ai-ttyd-docker -e
```

Verify ttyd is running:

```bash
ps aux | rg 'ttyd ' || true
# Should show: ttyd -i 0.0.0.0 -p 7681 -O -W -- ...
```

## Web terminal shows “Read-only file system” but WSL terminal works

The ttyd service runs under a user systemd unit. If that unit uses `ProtectHome=read-only`, only the **web terminal** becomes read-only.

Fix:

```bash
bash ./scripts/docker-setup
systemctl --user daemon-reload
systemctl --user restart ai-ttyd-docker
```

Verify the unit contains `ProtectHome=no`:

```bash
systemctl --user cat ai-ttyd-docker | rg ProtectHome
```

## tmux workspace/tab stuck or out of sync

The UI maps:

- **Workspaces** → tmux **sessions**
- **Tabs** → tmux **windows**

Useful commands:

```bash
tmux ls
tmux list-windows -t <session>
tmux kill-session -t <session>
tmux kill-window -t <session>:<window_index>
```

If the UI seems out of sync, use **Tools → Sync tabs** or refresh the page. If you updated tmux helper scripts, run:

```bash
bash ./scripts/ui-deploy
```

## Can't connect via Tailscale

1. Verify Tailscale Serve is configured:

   ```powershell
   tailscale serve status
   ```

2. Ensure “Shields Up” is disabled:

   ```powershell
   tailscale set --shields-up=false
   ```

3. Verify the Docker stack is running:

   ```bash
   docker compose ps
   curl http://127.0.0.1:8081/api/health
   ```

4. Verify Windows can reach nginx on localhost:
   ```powershell
   curl http://localhost:8081/
   ```
   If this fails, enable WSL localhost forwarding in `%UserProfile%\.wslconfig`:
   ```ini
   [wsl2]
   localhostForwarding=true
   ```
   Then run:
   ```powershell
   wsl --shutdown
   ```

## Browser shows old cached content

- Hard refresh: `Ctrl+Shift+R`
- Assets under `/assets/` are hashed and cached long-term; if you redeploy, you should see new hashes in `index.html`.

## Port 8081 is in use / UI still looks old after rebuild

If the browser keeps showing the old UI even after a rebuild, verify that Docker actually owns `127.0.0.1:8081`.

Check who is listening:

```bash
sudo ss -ltnp 'sport = :8081'
sudo lsof -iTCP:8081 -sTCP:LISTEN -Pn
```

If you see `docker-proxy` pointing to a container IP that no longer exists, it can be a stale Docker network. Find the network subnet and remove it:

```bash
docker network inspect $(docker network ls -q) --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}'
docker network inspect <network-name> --format '{{json .Containers}}'
docker network rm <network-name>
```

If the proxy remains, restart Docker (this restarts containers):

```bash
sudo service docker restart
```

Then rebuild nginx and hard refresh the browser:

```bash
UI_CACHEBUST=$(date +%s) docker compose up -d --build nginx
```
