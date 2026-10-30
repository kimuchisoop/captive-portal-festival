"""Retained lock files protect stopped-service configuration changes."""
from contextlib import contextmanager
from filesystem_guard import is_link,regular
from security import protect_directory
import os

@contextmanager
def owned_runtime(home,name):
    if name not in ('app','worker'): raise ValueError('Unknown runtime lock')
    directory=home/'runtime'
    if is_link(directory): raise ValueError('Linked runtime directory')
    directory.mkdir(exist_ok=True);protect_directory(directory)
    path=directory/(name+'.lock')
    if is_link(path): raise ValueError('Linked runtime lock')
    if path.exists():regular(path)
    with path.open('a+b') as handle:
        if os.fstat(handle.fileno()).st_size==0:handle.write(b'1');handle.flush()
        handle.seek(0);locked=False
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            locked=True;yield
        except OSError as error:
            if not locked: raise ValueError('Stop app and worker before changing configuration') from error
            raise
        finally:
            if locked and os.name=='nt':handle.seek(0);msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
