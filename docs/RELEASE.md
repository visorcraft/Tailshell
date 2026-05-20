# Release / Version tags

Set `TAILSHELL_RELEASE` to a value that uniquely identifies a deploy (git SHA, tag, or timestamp).

It is emitted in:
- API structured logs (`release`)
- `GET /api/health` (`release`)
- `GET /api/admin/system` (`release`)

Examples:

```bash
# Local deploy tag (git SHA)
export TAILSHELL_RELEASE="$(git rev-parse --short HEAD)"
docker compose up -d --build

# Simple timestamp tag
export TAILSHELL_RELEASE="$(date +%Y%m%d-%H%M%S)"
docker compose up -d --build
```
