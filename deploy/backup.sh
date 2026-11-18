#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
umask 077
mkdir -p backups
compose_file=${COMPOSE_FILE:-compose.production.yaml}
backup_file="backups/invite-$(date -u +%Y%m%d-%H%M%S).sqlite3"
temp_file=$(mktemp "${backup_file}.XXXXXX")
trap 'rm -f "$temp_file"' 0 HUP INT TERM
# Use SQLite's backup API rather than copying a database with an active WAL.
docker compose -f "$compose_file" exec -T invite python -c '
import os, sqlite3, sys, tempfile
fd, path = tempfile.mkstemp(suffix=".sqlite3")
os.close(fd)
try:
    with sqlite3.connect("/app/data/invite.sqlite3") as source:
        with sqlite3.connect(path) as target:
            source.backup(target)
    with open(path, "rb") as backup:
        sys.stdout.buffer.write(backup.read())
finally:
    os.unlink(path)
' > "$temp_file"
mv "$temp_file" "$backup_file"
find backups -type f -name 'invite-*.sqlite3' -mtime +7 -delete
printf 'Backup created: %s\n' "$backup_file"
