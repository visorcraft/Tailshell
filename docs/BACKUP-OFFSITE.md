# Offsite Backup Storage

This guide covers options for storing Tailshell backups offsite for disaster recovery.

## Prerequisites

- Backups are created by `scripts/mysql-backup` and stored in `backups/`
- Scheduled backups run daily via `scripts/backup-scheduler-setup`
- Local retention is 7 days (configurable via `TAILSHELL_BACKUP_KEEP_DAYS`)

## Option 1: Rclone (Recommended)

[Rclone](https://rclone.org/) supports 40+ cloud storage providers including S3, Google Drive, Dropbox, Backblaze B2, etc.

### Setup

```bash
# Install rclone
curl https://rclone.org/install.sh | sudo bash

# Configure a remote (interactive)
rclone config

# Example: Create an S3-compatible remote named "backup-s3"
```

### Sync After Backup

Add to `scripts/mysql-backup` or create a post-backup hook:

```bash
#!/usr/bin/env bash
# scripts/backup-offsite
set -euo pipefail

BACKUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/backups"
REMOTE="backup-s3:your-bucket/tailshell-backups"

# Sync backups to remote (only uploads new/changed files)
rclone sync "$BACKUP_DIR" "$REMOTE" --progress

# Optional: Delete remote backups older than 30 days
rclone delete "$REMOTE" --min-age 30d
```

### Automated Offsite Sync

Update the systemd service to run offsite sync after backup:

```ini
# ~/.config/systemd/user/tailshell-backup.service
[Service]
ExecStartPost=/path/to/scripts/backup-offsite
```

## Option 2: AWS S3

Direct S3 upload using AWS CLI:

```bash
# Install AWS CLI
sudo apt install awscli

# Configure credentials
aws configure

# Upload latest backup
aws s3 cp backups/tailshell-*.sql.gz s3://your-bucket/tailshell-backups/ --storage-class STANDARD_IA

# Lifecycle policy for automatic cleanup (set in S3 console or via CLI)
```

## Option 3: Backblaze B2

Cost-effective cloud storage:

```bash
# Install B2 CLI
pip install b2

# Authorize
b2 authorize-account <applicationKeyId> <applicationKey>

# Sync backups
b2 sync backups/ b2://your-bucket/tailshell-backups/
```

## Option 4: rsync to Remote Server

For self-hosted offsite storage:

```bash
# Sync to remote server via SSH
rsync -avz --delete backups/ user@remote-server:/backups/Tailshell/

# Add to crontab or systemd for automation
```

## Option 5: Git LFS (Small Databases Only)

For very small databases (<50MB), you could use Git LFS:

```bash
git lfs track "backups/*.sql.gz"
git add backups/
git commit -m "Backup $(date +%Y%m%d)"
git push
```

**Not recommended for production** - use a proper backup solution.

## Restore Drill

Periodically test that backups can be restored:

```bash
# Run the restore test (uses a temporary container)
./scripts/mysql-restore-test backups/tailshell-YYYYMMDD-HHMMSS.sql.gz
```

Schedule monthly restore drills:

```bash
# Add to crontab
0 3 1 * * /path/to/scripts/mysql-restore-test /path/to/backups/$(ls -t /path/to/backups/tailshell-*.sql.gz | head -1)
```

## Monitoring

Set up alerts for:

1. **Backup failures** - Check systemd journal for errors
2. **Missing backups** - Alert if no backup in last 24 hours
3. **Offsite sync failures** - Monitor rclone/AWS CLI exit codes
4. **Storage usage** - Alert when approaching storage limits

Example monitoring script:

```bash
#!/usr/bin/env bash
# scripts/backup-monitor
set -euo pipefail

BACKUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/backups"
MAX_AGE_HOURS=26  # Alert if newest backup is older than this

newest=$(find "$BACKUP_DIR" -name "tailshell-*.sql.gz" -type f -mmin -$((MAX_AGE_HOURS * 60)) | head -1)

if [ -z "$newest" ]; then
  echo "ALERT: No backup found in the last ${MAX_AGE_HOURS} hours!" >&2
  exit 1
fi

echo "OK: Latest backup is recent: $newest"
```

## Security Considerations

1. **Encrypt backups** before uploading to cloud storage:
   ```bash
   gpg --symmetric --cipher-algo AES256 backup.sql.gz
   ```

2. **Use IAM roles** with minimal permissions (write-only to backup bucket)

3. **Enable versioning** on S3/B2 buckets for protection against ransomware

4. **Test restores** regularly to ensure backups are valid

5. **Document recovery procedures** and keep them up to date
