# CI

GitHub Actions runs the workflow in `.github/workflows/ci.yml` on:
- `pull_request`
- `push` to `main`

## Jobs

### Docker Compose config
- Validates `docker compose config`

### API (install + lint + audit)
- `npm ci` - Install dependencies
- `npm run lint` - ESLint check
- `npm audit --omit=dev --audit-level=high` - Security audit
- `node --check src/index.js` - Syntax validation

### UI (lint + typecheck + build)
- `npm ci` - Install dependencies
- `npm run lint` - ESLint check
- `npm run typecheck` - TypeScript type checking
- `npm audit --omit=dev --audit-level=high` - Security audit
- `npm run build` - Production build

### Compose integration test
- Spins up MySQL + API containers
- Validates health endpoints
- Tests auth flow (login, password change)
- Tests CRUD + RBAC (readonly vs admin)
  - Script: `scripts/compose-integration-test`

## Notes

- CI uses `.node-version` (Vite 7 requires Node 20.19+ or 22.12+).
- Lint failures will block PRs - run `npm run lint:fix` locally to auto-fix issues.
- Type errors will block PRs - run `npm run typecheck` in the UI directory to check.
