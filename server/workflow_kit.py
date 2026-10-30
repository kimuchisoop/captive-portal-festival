"""Restore a verified v2 kit to a new home, preserving extracted evidence separately."""
from pathlib import Path
import os
from app import uid
from jobs import secure_new_file
from recovery_kit import consume
from stream_backup import file_hash
from security import protect_directory
from workflow_common import canonical

def restore_kit(source,key_file,destination,runtime,maintenance_file):
    from filesystem_guard import regular
    from workflow_backup import restore
    regular(source);regular(key_file);source=Path(source);destination=Path(destination).resolve()
    if destination.exists():raise ValueError('Destination exists')
    key=Path(key_file).read_bytes();proof=file_hash(source);manifest=consume(source,key)
    if manifest['format']!='festival-recovery-kit-v2':raise ValueError('Use the matching old release for legacy recovery')
    evidence=destination.with_name(destination.name+'-evidence-'+uid());evidence.mkdir(mode=0o700);protect_directory(evidence)
    secure_new_file(evidence/'recovery.incomplete',canonical(dict(source_sha256=proof)))
    consume(source,key,evidence)
    if file_hash(source)!=proof:raise ValueError('Recovery source changed')
    result=restore(evidence/'database.sffbackup',evidence/'files/backup.key',destination,runtime,maintenance_file,evidence/'files')
    secure_new_file(evidence/'restore-result.json',canonical(dict(**result,recovery_source_sha256=proof,original_files_preserved=True)))
    completed=evidence/('recovery-'+uid()+'.completed.json')
    if not completed.resolve().is_relative_to(evidence):raise ValueError('Unsafe completion marker')
    os.rename(evidence/'recovery.incomplete',completed)
    return result
