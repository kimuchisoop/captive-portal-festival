"""Explicit additive upgrade, preserving records. No production service is changed automatically."""
from pathlib import Path
from database import connect, Connection

def upgrade_from_v2(settings, home):
    from jobs import secure_new_file
    home=Path(home)
    marker=home/'upgrade.incomplete'
    raw=connect(settings);db=Connection(raw)
    try:
        version=db.execute("SELECT value FROM meta WHERE name='schema_version'").fetchone()
        if version and version[0]=='3' and not marker.exists():
            return False
        if not version or version[0] not in ('2','3'):
            raise ValueError('Only schema version 2 can be upgraded')
        if not marker.exists(): secure_new_file(marker,b'Additive upgrade in progress; preserve all files')
        if not db.execute("SHOW COLUMNS FROM notifications LIKE 'generation'").fetchone():
            db.execute('ALTER TABLE notifications ADD generation BIGINT NOT NULL DEFAULT 1')
        for sql in (Path(__file__).parent/'features-v3.sql').read_text(encoding='utf-8').split(';'):
            sql=sql.strip()
            if not sql: continue
            if sql.startswith('CREATE TRIGGER '):
                name=sql.split()[2]
                if db.execute('SELECT 1 FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND TRIGGER_NAME=?',(name,)).fetchone(): continue
            db.execute(sql)
        db.execute("UPDATE meta SET value='3' WHERE name='schema_version'")
        raw.commit()
        marker.unlink()  # A completion marker only; no log or record is removed.
        return True
    finally:
        raw.close()

def upgrade_to_v4(settings,home):
    from recovery_kit import stopped
    with stopped(Path(home)):
        return _upgrade_to_v4(settings,home)

def _upgrade_to_v4(settings,home):
    from jobs import secure_new_file
    home=Path(home);raw=connect(settings);db=Connection(raw)
    try:
        version=db.execute("SELECT value FROM meta WHERE name='schema_version'").fetchone()
        if not version or version[0] not in ('2','3','4'): raise ValueError('Unsupported source schema')
        old_version=version[0]
    finally: raw.close()
    if old_version=='2': upgrade_from_v2(settings,home)
    marker=home/'upgrade.incomplete'
    if old_version=='4' and not marker.exists(): return False
    if not marker.exists(): secure_new_file(marker,b'Additive schema 4 upgrade in progress')
    raw=connect(settings);db=Connection(raw)
    try:
        for sql in (Path(__file__).parent/'features-v4.sql').read_text(encoding='utf-8').split(';'):
            sql=sql.strip()
            if not sql: continue
            if sql.startswith('CREATE TRIGGER '):
                name=sql.split()[2]
                if db.execute('SELECT 1 FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND TRIGGER_NAME=?',(name,)).fetchone(): continue
            db.execute(sql)
        db.execute("UPDATE meta SET value='4' WHERE name='schema_version'");raw.commit()
        marker.unlink()
        return True
    finally: raw.close()
