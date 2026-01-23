# Security Notes

## Operational posture

- ttyd runs as a **user-level systemd service** (no root). The wrapper refuses to start as root unless `TAILSHELL_ALLOW_ROOT_TTYD=true`.
- Docker-published ports bind to `127.0.0.1` by default (not exposed to LAN).
- Auth uses `HttpOnly` cookies (`auth_token`, `terminal_token`, `refresh_token`, `refresh_session`, `csrf_token`) with `SameSite=Strict` (API also supports `Authorization: Bearer ...` for non-browser clients).
- CSRF protection is enforced on mutating routes when cookie auth is used (UI sends `X-CSRF-Token`).
- For HTTPS access (recommended via Tailscale Serve), set `TAILSHELL_COOKIE_SECURE=true` in `.env` so cookies are marked `Secure`.
- Access tokens are short-lived and refreshed via rotating refresh tokens (default: 15 minutes access / 7 days refresh) with server-side revocation.
- Admins can enable MFA/TOTP (recommended).
- Passwords are hashed with bcrypt (cost factor 12 by default) and validated against the strong password policy.
- Login rate limiting is enabled (default: 5 attempts per 15 minutes) with IP + username throttles.
- Audit logs record auth + CRUD events (who/what/when/from where).
- Terminal access is restricted by role (default: `admin`, `user`).
- Roles: `admin`, `user`, `editor`, `readonly`, `auditor` (endpoint access is enforced per role).
- Never commit `.env` or other secrets.

## CORS / API Access (Browser)

In normal operation (localhost or Tailscale Serve), the browser should access the API **through nginx** on the same origin:

- UI: `https://<machine>.<tailnet>.ts.net/`
- API: `https://<machine>.<tailnet>.ts.net/api/...` (or `http://localhost:8081/api/...`)

This does **not** require CORS because it’s same-origin. Avoid pointing the browser directly at the API port (e.g. `http://127.0.0.1:3000/...`) unless you’re intentionally doing cross-origin development.

To enable CORS for a separate frontend origin (default is disabled when `CORS_ORIGIN` is unset/empty):

1. Set `CORS_ORIGIN` in `.env` to a comma-separated allowlist of exact frontend origins (scheme + host + optional port), e.g.:
   - `CORS_ORIGIN=http://localhost:5173`
   - `CORS_ORIGIN=http://localhost:5173,https://my-ui.example.com`
2. Restart the API container:
   - `docker compose restart api`
3. Optional: if you intentionally need credentialed CORS requests, set `CORS_CREDENTIALS=true` (never use wildcard origins).

## Secrets and rotation

For production, prefer Docker secrets (or your secret manager of choice) instead of `.env` files. The API and MySQL support `_FILE` variants for secrets.

Example (Docker secrets):

- Create `secrets/mysql_root_password.txt`, `secrets/mysql_password.txt`, `secrets/jwt_secret.txt`
- Start with: `docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d --build`

Rotation checklist:

1. Generate new secrets and update the `secrets/*.txt` files (or your secrets manager).
2. Restart the stack (`docker compose up -d`).
3. For JWT rotation, ensure all users re-authenticate (existing refresh tokens will no longer validate).

## MFA/TOTP

Admins can enable MFA from the Admin → System panel. Once enabled, admin logins require a 6‑digit TOTP code.

## Login throttling + captcha

IP/username throttles are enforced in-memory. If `TAILSHELL_TURNSTILE_SITE_KEY` + `TAILSHELL_TURNSTILE_SECRET_KEY` are configured,
login will require a Turnstile captcha after repeated failures.

## TLS / HSTS

- Localhost remains HTTP-only (`http://localhost:8081`); cookies must not be `Secure` for this to work.
- Nginx emits an HSTS header that browsers will honor only over HTTPS.

## CSP

The UI and auth pages are served from nginx with strict CSP headers to avoid loading remote scripts/styles/fonts. Fonts are self-hosted.

## Third-party notices

See `THIRD_PARTY_NOTICES.md` for vendored third-party components (for example, self-hosted fonts) and their license texts.
