"""Backup and restore utilities for the application database.

Control: BACKUP-001 (Backup & Recovery)

Provides a simple offline backup and a restore test for the sqlite/sqlcipher database file.
"""
from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parents[3]
DB_FILE = BASE_DIR / "backend" / "data" / "ssd_app.db"
BACKUP_DIR = BASE_DIR / "backups"


def create_backup() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    target = BACKUP_DIR / f"ssd_app.db.{timestamp}.bak"
    shutil.copy2(DB_FILE, target)
    return target


def restore_test(backup_file: Path) -> bool:
    """Perform a simple restore test by copying backup to a temp file and ensuring it exists.

    Note: For SQLCipher-encrypted DBs a proper reconnection using the app's DB_ENCRYPTION_KEY
    should be performed. This function only performs a sanity copy test for the demo.
    """
    tmp_target = BACKUP_DIR / "restore_test.db"
    shutil.copy2(backup_file, tmp_target)
    return tmp_target.exists() and tmp_target.stat().st_size > 0


if __name__ == "__main__":
    b = create_backup()
    print("Created backup:", b)
    ok = restore_test(b)
    print("Restore test ok:", ok)
