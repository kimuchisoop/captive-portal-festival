"""Do not follow symlinks, junctions or other Windows reparse points in service files."""
import hashlib,stat
from pathlib import Path

def is_link(path):
    try: info=Path(path).lstat()
    except FileNotFoundError: return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0x400))

def regular(path):
    path=Path(path)
    if is_link(path) or not stat.S_ISREG(path.lstat().st_mode): raise ValueError('Regular unlinked file required')
    return path

def file_hash(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as handle:
        while block:=handle.read(1024*1024): digest.update(block)
    return digest.hexdigest()
