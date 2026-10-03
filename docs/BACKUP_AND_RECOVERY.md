# APIHub — Database Backup & Recovery Plan

This document outlines procedure for performing database backups, disaster recovery, and account data exports in APIHub.

---

## 1. PostgreSQL Production Database Backups

### Automated Daily Dump (pg_dump)

Run `pg_dump` via cron or container scheduled task:

```bash
# Direct PostgreSQL database backup
pg_dump -U apihub_user -h localhost -d apihub_db -F c -b -v -f /backups/apihub_backup_$(date +%Y%m%d_%H%M%S).dump
```

### Automated Backup Script (`backup.sh`)

```bash
#!/bin/bash
BACKUP_DIR="/var/backups/apihub"
TIMESTAMP=$(date +'%Y%m%d_%H%M%S')
DB_NAME="apihub_db"
DB_USER="apihub_user"

mkdir -p $BACKUP_DIR

pg_dump -U $DB_USER -d $DB_NAME -F c -f "$BACKUP_DIR/apihub_$TIMESTAMP.dump"

# Retain backups for 30 days
find $BACKUP_DIR -type f -name "*.dump" -mtime +30 -delete
```

---

## 2. PostgreSQL Restoration Procedure

To restore APIHub from a `.dump` backup file:

```bash
# Drop and recreate database
dropdb -U apihub_user apihub_db
createdb -U apihub_user apihub_db

# Restore database schema and records
pg_restore -U apihub_user -d apihub_db -v /backups/apihub_backup_20261004.dump
```

---

## 3. SQLite Development Database Backup

For local development environments running SQLite (`db.sqlite3`):

```bash
# Create SQLite snapshot
cp db.sqlite3 db.sqlite3.bak_$(date +%Y%m%d)
```

---

## 4. User Self-Service Account Export

Authenticated users can export their personal collections, saved requests, environments, and history through the web interface:

- **Web Route**: `GET /export-data/`
- **Output**: JSON payload attachment formatted as `apihub_export_<username>.json`.
