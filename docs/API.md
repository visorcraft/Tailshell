# API Reference

The API is normally accessed via nginx on the same origin (`/api/...`). Direct access to `http://127.0.0.1:3000` is typically only needed for debugging/admin scripting.

Notes:

- Cookie auth requires `X-CSRF-Token` on mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`).
- Bearer auth (`Authorization: Bearer ...`) can be used for scripts and does not require CSRF headers.

## Health

| Method | Endpoint      | Description             |
| ------ | ------------- | ----------------------- |
| GET    | `/api/health` | Liveness check          |
| GET    | `/api/ready`  | Readiness check (DB OK) |

## Authentication

| Method | Endpoint                    | Description                                   |
| ------ | --------------------------- | --------------------------------------------- |
| GET    | `/api/auth/options`         | Auth config for the UI (captcha, modes)       |
| POST   | `/api/auth/login`           | Login (sets cookies)                          |
| POST   | `/api/auth/refresh`         | Rotate refresh token + issue new access token |
| POST   | `/api/auth/logout`          | Revoke current session                        |
| GET    | `/api/auth/validate`        | Validate auth cookie (used by nginx)          |
| GET    | `/api/auth/me`              | Current user profile                          |
| POST   | `/api/auth/change-password` | Change password                               |
| GET    | `/api/terminal/validate`    | Validate terminal access (used by nginx)      |

### MFA (admin-only)

| Method | Endpoint                | Description             |
| ------ | ----------------------- | ----------------------- |
| GET    | `/api/auth/mfa`         | MFA status              |
| POST   | `/api/auth/mfa/setup`   | Begin TOTP enrollment   |
| POST   | `/api/auth/mfa/confirm` | Confirm TOTP enrollment |
| POST   | `/api/auth/mfa/disable` | Disable MFA             |

### Sessions

| Method | Endpoint                           | Description               |
| ------ | ---------------------------------- | ------------------------- |
| GET    | `/api/auth/sessions`               | List active sessions      |
| POST   | `/api/auth/sessions/revoke-others` | Revoke other sessions     |
| POST   | `/api/auth/sessions/:id/revoke`    | Revoke a specific session |

## Invites + Password Reset

| Method | Endpoint                      | Description             |
| ------ | ----------------------------- | ----------------------- |
| GET    | `/api/invites/:token`         | Inspect invite          |
| POST   | `/api/invites/:token/accept`  | Accept invite           |
| GET    | `/api/password-resets/:token` | Inspect reset token     |
| POST   | `/api/password-resets/:token` | Complete password reset |

## Workspaces

| Method | Endpoint                       | Description                                        |
| ------ | ------------------------------ | -------------------------------------------------- |
| GET    | `/api/workspaces`              | List workspaces                                    |
| POST   | `/api/workspaces`              | Create workspace                                   |
| POST   | `/api/workspaces/:id/activate` | Update last-used timestamp                         |
| PUT    | `/api/workspaces/:id`          | Update metadata (name, pinned, sort, default)      |
| POST   | `/api/workspaces/reorder`      | Reorder via `ids[]`                                |
| DELETE | `/api/workspaces/:id`          | Delete (requires `?confirm=true` if prompts exist) |

## Tags

| Method | Endpoint        | Description |
| ------ | --------------- | ----------- |
| GET    | `/api/tags`     | List tags   |
| POST   | `/api/tags`     | Create tag  |
| PUT    | `/api/tags/:id` | Update tag  |
| DELETE | `/api/tags/:id` | Delete tag  |

## Prompt Folders

| Method | Endpoint                      | Description     |
| ------ | ----------------------------- | --------------- |
| GET    | `/api/prompt-folders`         | List folders    |
| POST   | `/api/prompt-folders`         | Create folder   |
| PUT    | `/api/prompt-folders/:id`     | Update folder   |
| POST   | `/api/prompt-folders/reorder` | Reorder folders |
| DELETE | `/api/prompt-folders/:id`     | Delete folder   |

## Prompt Filters

| Method | Endpoint                  | Description   |
| ------ | ------------------------- | ------------- |
| GET    | `/api/prompt-filters`     | List filters  |
| POST   | `/api/prompt-filters`     | Create filter |
| PUT    | `/api/prompt-filters/:id` | Update filter |
| DELETE | `/api/prompt-filters/:id` | Delete filter |

## Prompts

| Method | Endpoint                          | Description                      |
| ------ | --------------------------------- | -------------------------------- |
| GET    | `/api/prompts`                    | List prompts                     |
| GET    | `/api/prompts/:id`                | Get prompt                       |
| POST   | `/api/prompts`                    | Create prompt                    |
| PUT    | `/api/prompts/:id`                | Update prompt                    |
| DELETE | `/api/prompts/:id`                | Delete prompt                    |
| GET    | `/api/prompts/:id/versions`       | Prompt version history           |
| POST   | `/api/prompts/:id/rollback`       | Roll back to a version           |
| GET    | `/api/prompts/:id/shares`         | List shared users                |
| POST   | `/api/prompts/:id/shares`         | Share prompt                     |
| DELETE | `/api/prompts/:id/shares/:userId` | Unshare prompt                   |
| POST   | `/api/prompts/:id/copy`           | Copy prompt to another workspace |
| GET    | `/api/prompts/export`             | Export prompts                   |
| POST   | `/api/prompts/import`             | Import prompts                   |
| POST   | `/api/prompts/bulk`               | Bulk create/update               |

## Activity

| Method | Endpoint               | Description          |
| ------ | ---------------------- | -------------------- |
| POST   | `/api/activity/prompt` | Log prompt activity  |
| GET    | `/api/activity/recent` | Recent activity feed |

## Admin

| Method | Endpoint                        | Description                              |
| ------ | ------------------------------- | ---------------------------------------- |
| GET    | `/api/users`                    | List users                               |
| POST   | `/api/users`                    | Create user                              |
| PUT    | `/api/users/:id`                | Update user                              |
| DELETE | `/api/users/:id`                | Delete user                              |
| GET    | `/api/admin/invites`            | List invites                             |
| POST   | `/api/admin/invites`            | Create invite                            |
| DELETE | `/api/admin/invites/:id`        | Revoke invite                            |
| POST   | `/api/admin/invites/:id/resend` | Resend invite                            |
| POST   | `/api/admin/invites/:id/reset`  | Reset invite token                       |
| GET    | `/api/admin/sessions`           | List all sessions                        |
| POST   | `/api/admin/sessions/revoke`    | Revoke a session                         |
| GET    | `/api/admin/audit`              | Audit log feed                           |
| GET    | `/api/admin/system`             | System status (includes circuit breaker) |
| GET    | `/api/admin/rate-limit`         | Rate limit status                        |
