# TLS certificates

This folder is used only when running the TLS/HTTP2 override:

```bash
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d --build
```

Provide:
- `tls.crt` (certificate chain)
- `tls.key` (private key)

These files are ignored by git (`*.crt`, `*.key`, etc).

