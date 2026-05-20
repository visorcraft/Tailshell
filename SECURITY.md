<!-- SPDX-FileCopyrightText: 2026 VisorCraft LLC -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Security and Privacy Policy

Tailshell is a self-hosted web terminal: it gives authenticated users
an interactive shell on the host (via ttyd + tmux), persists user
state in MySQL, and is reverse-proxied by nginx. This document
records the disclosure process and the threat model.

For the **operational hardening checklist** that production
deployments are expected to follow (HTTPS via Tailscale Serve,
cookie flags, CORS posture, secret handling, rate-limit tuning), see
[docs/SECURITY.md](docs/SECURITY.md).

## Reporting a vulnerability

**Do not file a public GitHub issue or pull request for security
problems.** Instead:

- Email the security contact at **security@visorcraft.com**.
- Include reproduction steps, the Tailshell git commit (`git rev-parse
  HEAD`), the deployment topology (single-user vs. multi-user,
  Tailscale Serve vs. direct, MFA on/off), and any relevant nginx /
  API logs with secrets redacted.
- We aim to acknowledge within 72 hours and to publish a patch +
  advisory within two weeks of confirming a fix.

Please give us a 30-day coordinated-disclosure window before going
public, unless the vulnerability is already actively exploited.

## Supported versions

The latest `master` branch is supported with security fixes. Older
tagged releases receive fixes only when the patch is trivial to
backport. Always run with the latest API + UI + nginx images pulled
together — running mismatched versions across the three layers is
unsupported.

## Telemetry policy

**Tailshell ships zero telemetry.** No analytics, no crash reports,
no ping-home behavior. The only outbound traffic Tailshell originates
on its own is:

- Container image pulls during `docker compose up` (from your
  configured registry).
- Tailscale Serve / Tailscale Funnel traffic, when the operator wires
  it up.

The application itself does not phone home. Operator-side
observability (audit logs, structured logs, Prometheus metrics) is
local-only by default and lives under the host's filesystem.

## Authentication and authorization

- JWTs are issued with short-lived access tokens (~15 minutes) and
  rotating refresh tokens (~7 days), each revocable server-side.
- Cookies are `HttpOnly` with `SameSite=Strict`. Production
  deployments must set `TAILSHELL_COOKIE_SECURE=true` so cookies are
  also marked `Secure`.
- CSRF protection is enforced on mutating routes when cookie auth is
  used. The UI sends `X-CSRF-Token`; the API rejects mutations that
  don't carry it.
- Passwords are hashed with **bcrypt** at cost factor 12 and
  validated against the strong password policy.
- Login attempts are rate-limited (default: 5 attempts per 15 minutes,
  per IP + per username).
- Admins can enable **TOTP-based MFA** (and should). MFA is enforced
  per role.
- Roles: `admin`, `user`, `editor`, `readonly`, `auditor`. Endpoint
  access is enforced per role; routes that mutate global state are
  admin-only.

## Terminal access

- **ttyd runs as an unprivileged user-level systemd service.** The
  wrapper refuses to start as root unless
  `TAILSHELL_ALLOW_ROOT_TTYD=true` is set explicitly.
- Terminal access is gated by role and by an additional
  `terminal_token` cookie that scopes WebSocket connections to a
  single authenticated session.
- tmux sessions are namespaced per user so workspace isolation does
  not depend on shell discipline.
- The reverse proxy refuses upgrade requests without a valid
  `terminal_token`.

## Database and persistence

- MySQL is reached over the internal Docker network only;
  `docker-compose.yml` binds the port to `127.0.0.1`.
- Database access goes through Knex with parameterized queries.
- Audit log entries (auth events + CRUD on workspaces, prompts,
  invitations, password resets) are written into the audit table
  with the actor, action, target, source IP, and timestamp.
- Refresh-token rotation, MFA challenges, and password-reset tokens
  are stored hashed; the plaintext is never persisted.

## Secrets and configuration

- `.env` is in `.gitignore`. The `.env.example` file lists every
  variable Tailshell reads.
- Production deployments should prefer **Docker secrets** or an
  external secret manager over `.env` files. The API and MySQL
  containers support `*_FILE` variants for sensitive values
  (`JWT_SECRET_FILE`, `MYSQL_PASSWORD_FILE`, etc.).
- TLS certificates live under `nginx/certs/` and are mounted
  read-only into the nginx container.

## Outbound traffic from user shells

Tailshell does **not** sandbox the shells it spawns. A user with a
terminal session can run any command their Unix account is allowed
to run, including outbound network traffic. This is intentional —
the whole point of the product is to be a real shell — but operators
should configure their host's outbound firewall, Tailscale ACLs, or
egress proxy according to their threat model.

## CORS and cross-origin posture

CORS is **disabled by default**. The expected production layout is
same-origin: the UI and API are served from the same hostname (via
nginx) so no preflight requests are needed.

If you intentionally serve the UI from a separate origin, set
`CORS_ORIGIN` to an exact allowlist (never `*`). Credentialed CORS
requires `CORS_CREDENTIALS=true` and a non-wildcard origin.

## Threat model summary

| Threat | Mitigation |
| ------ | ---------- |
| Stolen access cookie replayed from another host | `SameSite=Strict` cookies, short access-token TTL, `Secure` flag in HTTPS deployments, IP-bound refresh sessions. |
| Brute-force login | Per-IP + per-username login rate limit; admins can require MFA. |
| CSRF against a mutating route | Every mutating endpoint requires `X-CSRF-Token` matched to the `csrf_token` cookie when cookie auth is used. |
| Terminal hijack via WebSocket upgrade | The proxy refuses upgrades without a valid `terminal_token` cookie; ttyd is bound to a tmux session that belongs to the authenticated user. |
| Privilege escalation via the ttyd service | ttyd runs as an unprivileged user-level service; the wrapper refuses root unless explicitly opted in. |
| SQL injection | All queries go through Knex's parameterized builder; no string concatenation in handlers. |
| Refresh-token theft | Refresh tokens are hashed at rest, rotated on use, and revocable server-side. The session table tracks revocations. |
| Password leak through logs | The API logger is configured to drop request bodies on `/login`, `/reset-password`, `/change-password`, and the MFA endpoints. |
| Audit-log tampering by a compromised admin | Audit entries are append-only at the application layer; rotating offsite backups (see `docs/BACKUP-OFFSITE.md`) defeat in-place tampering. |
| Exposed Docker socket | Tailshell does not require host access to the Docker socket. Operators who mount it should know the implications. |
| Direct access to MySQL from the public internet | The compose file binds MySQL to `127.0.0.1`; Tailscale-only deployments add a second layer of defense. |
| Stale invite token replay | Invitation tokens are single-use, scoped by email, and expire by default; the API rejects reuse with a structured error. |

## Dependency hygiene

- `npm audit` is run during CI on every push.
- Dependabot opens weekly PRs for transitive and direct npm updates;
  please review and merge them once CI is green.
- Container base images (`node`, `nginx`, `mysql`) are pinned by tag
  in the compose files; bump them in a dedicated PR so the change is
  easy to revert.
